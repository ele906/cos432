import java.io.*;
import java.util.Arrays;

// This is just like an InsecureChannel, except that it provides
//    authenticated encryption for the messages that pass
//    over the channel.   It also guarantees that messages are delivered
//    on the receiving end in the same order they were sent (returning
//    null otherwise).  Also, when the channel is first set up,
//    the client authenticates the server's identity, and the necessary
//    steps are taken to detect any man-in-the-middle (and to close the
//    connection if a MITM is detected).
//
// The code provided here is not secure --- all it does is pass through
//    calls to the underlying InsecureChannel.

public class SecureChannel extends InsecureChannel {

    private AuthEncryptor enc; private AuthDecryptor dec;

    // separate locks for send + receive
    private final Object sendLock = new Object();
    private final Object recvLock = new Object();

    // sequence numbers counters
    private long sendSeq = 0, recvSeq = 0;

    // symmetric keys
    private byte[] kC2S; // client -> server
    private byte[] kS2C; // server -> client

    private static final long MAX_TIMEOUT_MS = 35_000;
    private static final int MAX_MSG_LEN = 1 << 20;

    private final InputStream inStream;
    private final OutputStream outStream;

    public SecureChannel(InputStream inStr, OutputStream outStr,
                         PRGen rand, boolean iAmServer,
                         RSAKey serverKey) throws IOException {
        super(inStr, outStr);

        this.inStream = inStr;
        this.outStream = outStr;
        byte[] sharedSecret = null;

        try {
            // --- DHKE ---
            KeyExchange kx = new KeyExchange(rand, iAmServer);
            byte[] myDH = kx.prepareOutMessage();
            writeFrame(myDH);

            byte[] otherDH = readFrameWithTimeout(MAX_TIMEOUT_MS);
            if (otherDH == null) throw new IOException("handshake: missing DH");

            sharedSecret = kx.processInMessage(otherDH);
            if (sharedSecret == null) throw new IOException("handshake: bad DH");

            // --- Server authentication w RSA ---
            byte[] DHClient = iAmServer ? otherDH : myDH;
            byte[] DHServer = iAmServer ? myDH : otherDH;
            byte[] transcript = mergeArr(DHClient, DHServer);

            if (iAmServer) {
                byte[] signature = serverKey.sign(transcript, rand);
                writeFrame(signature);
            } else {
                byte[] sig = readFrameWithTimeout(MAX_TIMEOUT_MS);
                if (sig == null || sig.length == 0) throw new IOException("missing signature");
                if (!serverKey.verifySignature(transcript, sig)) {
                    throw new IOException("invalid signature. possible MITM");
                }
            }

            // --- directional keys from shared secret ---
            PRF prf = new PRF(sharedSecret);
            byte[] tmpC2S = prf.eval(new byte[]{0x00});
            byte[] tmpS2C = prf.eval(new byte[]{0x01});

            if (tmpC2S == null || tmpS2C == null) throw new IOException("handshake: PRF null");
            if (tmpC2S.length < AuthEncryptor.KEY_SIZE_BYTES || tmpS2C.length < AuthEncryptor.KEY_SIZE_BYTES)
                throw new IOException("handshake: PRF too short");

            kC2S = Arrays.copyOf(tmpC2S, AuthEncryptor.KEY_SIZE_BYTES);
            kS2C = Arrays.copyOf(tmpS2C, AuthEncryptor.KEY_SIZE_BYTES);

            if (iAmServer) {
                // server encrypts outgoing with kS2C, decrypts incoming with kC2S
                this.enc = new AuthEncryptor(kS2C);
                this.dec = new AuthDecryptor(kC2S);
            } else {
                // client is the opposite
                this.enc = new AuthEncryptor(kC2S);
                this.dec = new AuthDecryptor(kS2C);
            }
        }
        catch (IOException e) {
            try { close(); } catch (IOException ignored) {}
            throw e;
        } catch (Exception e) {
            try { close(); } catch (IOException ignored) {}
            throw new IOException("handshake failed", e);
        }
        finally {
            if (sharedSecret != null) Arrays.fill(sharedSecret, (byte) 0); // wipe secret
        }
    }

    @Override
    public void sendMessage(byte[] message) throws IOException {
        if (message == null) throw new IOException("null message");
        if (enc == null) throw new IOException("encryptor not initialized");

        synchronized (sendLock) {
            long s = sendSeq++;
            if (s > Integer.MAX_VALUE) { close(); throw new IOException("seq overflow"); }
            byte[] plaintext = mergeArr(intToByteArr((int) s), message);
            byte[] nonce = getNonceFromSeq(s);

            byte[] finalMsg = enc.authEncrypt(plaintext, nonce, false);
            writeFrame(finalMsg);
        }
    }

    @Override
    public byte[] receiveMessage() throws IOException {
        if (dec == null) throw new IOException("decrypter not initialized");

        synchronized (recvLock) {
            byte[] message = readFrame();
            if (message == null) return null;

            // get nonce from our receive counter
            byte[] nonce = getNonceFromSeq(recvSeq);
            byte[] plaintext = dec.authDecrypt(message, nonce);

            // MAC check
            if (plaintext == null || plaintext.length < 4) return null;
            if (recvSeq > Integer.MAX_VALUE) return null;
            int expectedPlaintext = (int) recvSeq;

            int testPlaintext = bytesToInt(plaintext, 0);
            if (testPlaintext != expectedPlaintext) return null;

            recvSeq++;

            byte[] outMsg = new byte[plaintext.length - 4];
            System.arraycopy(plaintext, 4, outMsg, 0, outMsg.length);
            return outMsg;
        }
    }

    private void writeFrame(byte[] msg) throws IOException {
        outputInt(outStream, msg.length);
        outStream.write(msg);
        outStream.flush();
    }

    private byte[] readFrame() throws IOException {
        int len = readIntBlocking();
        if (len < 0) return null;
        if (len > MAX_MSG_LEN) { close(); return null; }

        byte[] buf = new byte[len];
        readFullyBlocking(buf, 0, len);
        return buf;
    }

    private byte[] readFrameWithTimeout(long timeoutMs) throws IOException {
        long deadline = System.currentTimeMillis() + timeoutMs;

        int len = readIntWithTimeout(deadline);
        if (len < 0) return null;
        if (len > MAX_MSG_LEN) { close(); throw new IOException("frame too large"); }

        byte[] buf = new byte[len];
        readEverythingWithTimeout(buf, 0, len, deadline);
        return buf;
    }

    private int readIntWithTimeout(long deadline) throws IOException {
        byte[] b = new byte[4];
        readEverythingWithTimeout(b, 0, 4, deadline);
        return bytesToInt(b, 0);
    }

    private int readIntBlocking() throws IOException {
        byte[] b = new byte[4];
        readFullyBlocking(b, 0, 4);
        return bytesToInt(b, 0);
    }

    private void readEverythingWithTimeout(byte[] b, int off, int len, long deadline) throws IOException {
        int n = 0;
        while (n < len) {
            if (System.currentTimeMillis() > deadline) {
                close();
                throw new IOException("handshake timed out");
            }
            int avail = inStream.available();
            if (avail <= 0) {
                try { Thread.sleep(1); } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    close();
                    throw new IOException("interrupted");
                }
                continue;
            }
            int r = inStream.read(b, off + n, len - n);
            if (r < 0) { close(); throw new EOFException(); }
            n += r;
        }
    }

    private void readFullyBlocking(byte[] b, int off, int len) throws IOException {
        int n = 0;
        while (n < len) {
            int r = inStream.read(b, off + n, len - n);
            if (r < 0) throw new EOFException();
            n += r;
        }
    }

    private static void outputInt(OutputStream out, int x) throws IOException {
        out.write((x >>> 24) & 0xFF);
        out.write((x >>> 16) & 0xFF);
        out.write((x >>>  8) & 0xFF);
        out.write((x) & 0xFF);
    }

    // sequence number as a big-endian byte array sized to NONCE_SIZE_BYTES.
    private static byte[] getNonceFromSeq(long seq) {
        byte[] nonce = new byte[AuthEncryptor.NONCE_SIZE_BYTES];
        long x = seq;
        for (int i = nonce.length - 1; i >= 0; i--) {
            nonce[i] = (byte) (x & 0xFF);
            x >>>= 8;
        }
        return nonce;
    }

    private static byte[] mergeArr(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static byte[] intToByteArr(int x) {
        return new byte[] {(byte) (x >>> 24), (byte) (x >>> 16),
                (byte) (x >>>  8), (byte) (x)};
    }

    private static int bytesToInt(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 24) | ((b[offset + 1] & 0xFF) << 16) |
                ((b[offset + 2] & 0xFF) <<  8) | ((b[offset + 3] & 0xFF));
    }

    @Override
    public void close() throws IOException {
        // zero out key from memory before releasing references
        if (kC2S != null) { Arrays.fill(kC2S, (byte)0); kC2S = null; }
        if (kS2C != null) { Arrays.fill(kS2C, (byte)0); kS2C = null; }
        enc = null; dec = null;
        super.close();
    }
}
