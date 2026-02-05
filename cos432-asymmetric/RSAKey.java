import java.math.BigInteger;

/***
 * This class represents a single RSA key that can perform the RSA encryption and signing algorithms discussed in
 * class. Note that some of the public methods would normally not be part of a production API, but we leave them
 * public for the sake of grading.
 */
public class RSAKey {
    private BigInteger exponent;
    private BigInteger modulus;
    private int hLen = 32;

    /***
     * Constructor. Create an RSA key with the given exponent and modulus.
     *
     * @param theExponent exponent to use for this key's RSA math
     * @param theModulus modulus to use for this key's RSA math
     */
    public RSAKey(BigInteger theExponent, BigInteger theModulus) {
        exponent = theExponent;
        modulus = theModulus;
    }

    /***
     * Get the exponent used for this key's encryption/decryption.
     *
     * @return BigInteger containing this key's exponent
     */
    public BigInteger getExponent() {
        return exponent;
    }

    /***
     * Get the modulus used for this key's encryption/decryption.
     *
     * @return BigInteger containing this key's modulus
     */
    public BigInteger getModulus() {
        return modulus;
    }

    /***
     * Pad plaintext input if it is too short for OAEP. Do not call this from {@link #encodeOaep(byte[], PRGen)}.
     *
     * In a "real world" application, this would be a private helper function, but for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * <pre>{@code
     *  byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *  byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input plaintext to pad
     * @return padded plaintext of appropriate length for OAEP
     */
    public byte[] addPadding(byte[] input) {
        int k = (this.modulus.bitLength() + 7) / 8;
        int L = k - 2 * hLen - 2; int n = input.length;
        if (n + 4 > L) throw new IllegalArgumentException("Input too long");

        byte[] out = new byte[L];
        out[0] = (byte)(n >>> 24); out[1] = (byte)(n >>> 16);
        out[2] = (byte)(n >>> 8); out[3] = (byte)(n);

        for(int i = 0; i < n; i++){
            out[i+4] = input[4];
        }
        return out;
    }

    /***
     * Remove padding applied by {@link #addPadding(byte[])} method. Do not call this from {@link #decodeOaep(byte[])}.
     *
     * In a "real world" application, this would be a private helper function, but for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * <pre>{@code
     *  byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *  byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input padded plaintext from which we extract plaintext
     * @return plaintext in {@code input} without padding
     */
    public byte[] removePadding(byte[] input) {
        // IMPLEMENT THIS
        return null;
    }

    /***
     * Encode a plaintext input with OAEP method. May require basic padding before calling. Do not call
     * {@link #addPadding(byte[])} from this method.
     *
     * In a "real world" application, this would be a private helper function, but for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * <pre>{@code
     *  byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *  byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input plaintext to encode
     * @param prgen pseudo-random generator to use in encoding algorithm
     * @return OAEP encoded plaintext
     */
    public byte[] encodeOaep(byte[] input, PRGen prgen) {
        // IMPLEMENT THIS
        return null;
    }

    /***
     * Decode an OAEP encoded message back into its plaintext representation. May require padding removal after calling.
     * Do not call {@link #removePadding(byte[])} from this method.
     *
     * In a "real world" application, this would be a private helper function, but for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * <pre>{@code
     *  byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *  byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input OEAP encoded message
     * @return decoded plaintext message
     */
    public byte[] decodeOaep(byte[] input) {
        // IMPLEMENT THIS
        return null;
    }

    /***
     * Get the largest N such that any plaintext of size N bytes can be encrypted with this key and padding/encoding.
     *
     * @return upper bound of plaintext length applicable for this key
     */
    public int maxPlaintextLength() {
        // IMPLEMENT THIS
        return 0;
    }

    /***
     * Encrypt the given plaintext message using RSA algorithm with this key.
     *
     * @param plaintext message to encrypt
     * @param prgen pseudorandom generator to be used for encoding/encryption
     * @return ciphertext result of RSA encryption on this plaintext/key
     */
    public byte[] encrypt(byte[] plaintext, PRGen prgen) {
        if (plaintext == null) throw new NullPointerException();

        // IMPLEMENT THIS
        return null;
    }

    /***
     * Decrypt the given ciphertext message using RSA algorithm with this key. Effectively the inverse of our
     * {@link #encrypt(byte[], PRGen)} method.
     *
     * @param ciphertext encrypted message to decrypt
     * @return plaintext message
     */
    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null) throw new NullPointerException();

        // IMPLEMENT THIS
        return null;
    }

    /***
     * Create a digital signature on {@code message}. The signature need not contain the contents of {@code message}; we
     * will assume that a party who wants to verify the signature will already know with which message this signature is
     * meant to be associated.
     *
     * @param message message to sign
     * @param prgen pseudorandom generator used for signing
     * @return RSA signature of the message using this key
     */
    public byte[] sign(byte[] message, PRGen prgen) {
        if (message == null) throw new NullPointerException();

        // IMPLEMENT THIS
        return null;
    }

    /***
     * Verify a digital signature against this key. Returns true if and only if {@code signature} is a valid RSA
     * signature on {@code message}; returns false otherwise. A "valid" RSA signature is one that was created by calling
     * {@link #sign(byte[], PRGen)} with the same message on the other RSAKey that belongs to the same RSAKeyPair as
     * this RSAKey object.
     *
     * @param message message that has been signed
     * @param signature signature to validate against this key
     * @return true iff this RSAKey object's counterpart in a keypair signed the given message and produced the given
     * signature
     */
    public boolean verifySignature(byte[] message, byte[] signature) {
        if ((message == null) || (signature == null)) throw new NullPointerException();

        // IMPLEMENT THIS
        return false;
    }
}
