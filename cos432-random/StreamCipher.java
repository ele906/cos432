/**********************************************************************************/
/* StreamCipher.java                                                              */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: This class implements a stream cipher, which encrypts or decrypts */
/*              a stream of bytes (the two operations are identical).             */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Implement a stream cipher.                                          */
/* ------------------------------------------------------------------------------ */
/* USAGE: Create a new StreamCipher with key k of length <KEY_SIZE_BYTES> and     */
/*        nonce n of length NONCE_SIZE_BYTES:                                     */
/*            StreamCipher enc = new StreamCipher(k, n);                          */
/*                                                                                */
/*        Encrypt two bytes b1 and b2:                                            */
/*            byte e1 = enc.cryptByte(b1);                                        */
/*            byte e2 = enc.cryptByte(b2);                                        */
/*                                                                                */
/*        Decrypt two bytes e1 and e2.  First, create a StreamCipher with the     */
/*        same key and nonce, and then call cryptByte() on the encrypted bytes in */
/*        the same order.                                                         */
/*            StreamCipher dec = new StreamCipher(k, n);                          */
/*            byte d1 = dec.cryptByte(e1);                                        */
/*            byte d2 = dec.cryptByte(e2);                                        */
/*            assert (d1 == b1 && d2 == b2);                                      */
/**********************************************************************************/
public class StreamCipher {
    // Class constants.
    public static final int KEY_SIZE_BYTES   = PRGen.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = 8;

    // Instance variables.
    private PRGen prg;

    // Creates a new StreamCipher with key <key> and nonce composed of
    // nonceArr[nonceOffset] through nonceArr[nonceOffset + NONCE_SIZE_BYTES - 1].
    public StreamCipher(byte[] key, byte[] nonceArr, int nonceOffset) {
        assert key.length == KEY_SIZE_BYTES;
        assert nonceOffset >= 0;
        assert nonceOffset + NONCE_SIZE_BYTES <= nonceArr.length;

        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        for (int i = 0; i < NONCE_SIZE_BYTES; i++) {
            nonce[i] = nonceArr[nonceOffset + i];
        }

        byte[] seed = new PRF(key).eval(nonce);
        prg = new PRGen(seed);
    }

    public StreamCipher(byte[] key, byte[] nonce) {
        this(key, nonce, 0); // Call the other constructor.
    }

    // Encrypts or decrypts the next byte in the stream.
    public byte cryptByte(byte in) {
        byte keystream = (byte) prg.next(8);
        return (byte)(in ^ keystream);
    }

    // Encrypts or decrypts multiple bytes.
    // Encrypts or decrypts inBuf[inOffset] through inBuf[inOffset + numBytes - 1],
    // storing the result in outBuf[outOffset] through outBuf[outOffset + numBytes - 1].
    public void cryptBytes(byte[]  inBuf, int  inOffset,
                           byte[] outBuf, int outOffset, int numBytes) {
        assert inOffset >= 0 && outOffset >= 0;
        assert numBytes > 0;
        assert inBuf != null && outBuf != null;
        assert (inOffset + numBytes <= inBuf.length) && (outOffset + numBytes <= outBuf.length);

        for(int i = 0; i < numBytes; i++){
            outBuf[outOffset + i] = cryptByte(inBuf[inOffset + i]);
        }
    }
}
