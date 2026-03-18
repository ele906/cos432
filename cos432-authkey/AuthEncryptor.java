/**********************************************************************************/
/* AuthEncryptor.java                                                             */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated encryption of data.                        */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Implement authenticated encryption, ensuring:                       */
/*            (1) Confidentiality: the only way to recover encrypted data is to   */
/*                perform authenticated decryption with the same key and nonce    */
/*                used to encrypt the data.                                       */
/*            (2) Integrity: A party decrypting the data using the same key and   */
/*                nonce that were used to encrypt it can verify that the data has */
/*                not been modified since it was encrypted.                       */
/*                                                                                */
/**********************************************************************************/
public class AuthEncryptor {
    // Class constants.
    public static final int KEY_SIZE_BYTES = StreamCipher.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = StreamCipher.NONCE_SIZE_BYTES;

    // Instance variables.
    private final byte[] encKey, macKey;

    public AuthEncryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;
        PRF prf = new PRF(key);

        // get encKey using label 0x00...
        byte[] labelEnc = new byte[] { 0x00 };
        byte[] prfEnc = prf.eval(labelEnc);
        this.encKey = new byte[StreamCipher.KEY_SIZE_BYTES];
        System.arraycopy(prfEnc, 0, encKey, 0, encKey.length);

        // get macKey using label 0x01...
        byte[] labelMac = new byte[] { 0x01 };
        byte[] prfMac = prf.eval(labelMac);
        this.macKey = new byte[PRF.KEY_SIZE_BYTES];
        System.arraycopy(prfMac, 0, macKey, 0, macKey.length);
    }

    // helper function to concatenate two arrays
    private static byte[] concatArr(byte[] a, byte[] b) {
        byte[] res = new byte[a.length + b.length];
        System.arraycopy(a, 0, res, 0, a.length);
        System.arraycopy(b, 0, res, a.length, b.length);
        return res;
    }

    // Encrypts the contents of <in> so that its confidentiality and integrity are protected against those who do not
    //     know the key and nonce.
    // If <nonceIncluded> is true, then the nonce is included in plaintext with the output.
    // Returns a newly allocated byte[] containing the authenticated encryption of the input.
    public byte[] authEncrypt(byte[] in, byte[] nonce, boolean includeNonce) {
        assert nonce != null && nonce.length == NONCE_SIZE_BYTES;
        if (in == null) throw new IllegalArgumentException("null plaintext");

        // plaintext -> ciphertext
        byte[] ciphertext = new byte[in.length];
        StreamCipher sc = new StreamCipher(encKey, nonce);
        sc.cryptBytes(in, 0, ciphertext, 0, in.length);

        // tag = PRF(macKey)( nonce || ciphertext )
        PRF macPRF = new PRF(macKey);
        byte[] MAC = concatArr(nonce, ciphertext);
        byte[] macValue = macPRF.eval(MAC);  // length = PRF.OUTPUT_SIZE_BYTES

        // output fmt
        if (includeNonce) {
            byte[] out = new byte[nonce.length + ciphertext.length + macValue.length];
            int idx = 0;
            System.arraycopy(nonce, 0, out, idx, nonce.length); idx += nonce.length;
            System.arraycopy(ciphertext, 0, out, idx, ciphertext.length); idx += ciphertext.length;
            System.arraycopy(macValue, 0, out, idx, macValue.length);
            return out;
        } else {
            byte[] out = new byte[ciphertext.length + macValue.length];
            int idx = 0;
            System.arraycopy(ciphertext, 0, out, idx, ciphertext.length); idx += ciphertext.length;
            System.arraycopy(macValue, 0, out, idx, macValue.length);
            return out;
        }
    }
}
