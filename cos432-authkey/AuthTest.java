public class AuthTest {
    public static void main(String[] args) {
        byte[] key = new byte[AuthEncryptor.KEY_SIZE_BYTES];
        for (int i = 0; i < key.length; i++) key[i] = (byte) i;

        byte[] nonce = new byte[AuthEncryptor.NONCE_SIZE_BYTES];
        for (int i = 0; i < nonce.length; i++) nonce[i] = (byte) (100 + i);

        byte[] msg = "hello world".getBytes();

        AuthEncryptor enc = new AuthEncryptor(key);
        AuthDecryptor dec = new AuthDecryptor(key);

        // includeNonce = true
        byte[] ct = enc.authEncrypt(msg, nonce, true);
        byte[] pt = dec.authDecrypt(ct);
        System.out.println("decrypt(includeNonce=true) ok? " + java.util.Arrays.equals(msg, pt));

        // tamper
        ct[ct.length / 2] ^= 0x01;
        byte[] pt2 = dec.authDecrypt(ct);
        System.out.println("tamper detected? " + (pt2 == null));

        // includeNonce = false
        byte[] ct3 = enc.authEncrypt(msg, nonce, false);
        byte[] pt3 = dec.authDecrypt(ct3, nonce);
        System.out.println("decrypt(includeNonce=false) ok? " + java.util.Arrays.equals(msg, pt3));
    }
}
