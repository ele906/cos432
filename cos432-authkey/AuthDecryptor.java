/**********************************************************************************/
/* AuthDecrytor.java                                                              */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated decryption of data encrypted using         */
/*              AuthEncryptor.java.                                               */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Decrypt data encrypted by your implementation of AuthEncryptor.java */
/*            if provided with the appropriate key and nonce.  If the data has    */
/*            been tampered with, return null.                                    */
/*                                                                                */
/**********************************************************************************/

public class AuthDecryptor {
    // Class constants.
    public static final int KEY_SIZE_BYTES = AuthEncryptor.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = AuthEncryptor.NONCE_SIZE_BYTES;

    // Instance variables.
    private final byte[] encKey, macKey;

    public AuthDecryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;
        PRF prf = new PRF(key);

        byte[] labelEnc = new byte[] { 0x00 };
        byte[] encPRF = prf.eval(labelEnc);
        this.encKey = new byte[StreamCipher.KEY_SIZE_BYTES];
        System.arraycopy(encPRF, 0, encKey, 0, encKey.length);

        byte[] labelMac = new byte[] { 0x01 };
        byte[] macPRF = prf.eval(labelMac);
        this.macKey = new byte[PRF.KEY_SIZE_BYTES];
        System.arraycopy(macPRF, 0, macKey, 0, macKey.length);
    }

    private static byte[] concatArr(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce has been included in <in>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] authDecrypt(byte[] in) {
        int MACvalueSize = PRF.OUTPUT_SIZE_BYTES;
        if (in == null || in.length < NONCE_SIZE_BYTES + MACvalueSize) return null;

        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        System.arraycopy(in, 0, nonce, 0, NONCE_SIZE_BYTES); // first nonce_size values of in is the nonce

        int remainingMsgLen = in.length - NONCE_SIZE_BYTES;
        byte[] remainingMsg = new byte[remainingMsgLen];
        System.arraycopy(in, NONCE_SIZE_BYTES, remainingMsg, 0, remainingMsgLen);

        return authDecrypt(remainingMsg, nonce);
    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce used to encrypt the data is provided in <nonce>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] authDecrypt(byte[] in, byte[] nonce) {
        assert nonce != null && nonce.length == NONCE_SIZE_BYTES;

        int MACValueSize = PRF.OUTPUT_SIZE_BYTES;
        if (in == null || in.length < MACValueSize) return null;

        int cipherLen = in.length - MACValueSize;
        byte[] ciphertext = new byte[cipherLen];
        byte[] MACValue = new byte[MACValueSize];

        System.arraycopy(in, 0, ciphertext, 0, cipherLen);
        System.arraycopy(in, cipherLen, MACValue, 0, MACValueSize);

        // expected tag
        PRF macPRF = new PRF(macKey);
        byte[] testMAC = concatArr(nonce, ciphertext);
        byte[] expected = macPRF.eval(testMAC);
        if (!constTimeCmp(MACValue, expected)) return null;

        // decrypt
        byte[] plaintext = new byte[cipherLen];
        StreamCipher sc = new StreamCipher(encKey, nonce);
        sc.cryptBytes(ciphertext, 0, plaintext, 0, cipherLen);
        return plaintext;
    }

    private boolean constTimeCmp(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int x = 0;
        for (int i = 0; i < a.length; i++) x |= (a[i] ^ b[i]);
        return x == 0;
    }
}
