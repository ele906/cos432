import java.math.BigInteger;

/***
 * This class represents a pair of RSA keys to be used for asymmetric encryption.
 */
public class RSAKeyPair {
    private RSAKey publicKey;
    private RSAKey privateKey;
    private BigInteger p;
    private BigInteger q;
    /***
     * Create an RSA key pair.
     *
     * @param rand PRGen that this class can use to get pseudorandom bits
     * @param numBits size in bits of each of the primes that will be used
     */
    public RSAKeyPair(PRGen rand, int numBits) {
        // IMPLEMENT THIS
        throw new RuntimeException("Unimplemented.");
    }

    /***
     * Get the public key from this keypair.
     *
     * @return public RSAKey corresponding to this pair
     */
    public RSAKey getPublicKey() {
        return publicKey;
    }

    /***
     * Get the private key from this keypair.
     *
     * @return private RSAKey corresponding to this pair
     */
    public RSAKey getPrivateKey() {
        return privateKey;
    }

    /***
     * Get an array containing the two primes that were used in this KeyPair's generation. In real life, this wouldn't
     * usually be necessary (we don't always keep track of the primes used for generation). Including this function here
     * is for grading purposes.
     *
     * @return two-element array of BigIntegers containing both of the primes used to generate this KeyPair
     */
    public BigInteger[] getPrimes() {
        BigInteger[] primes = new BigInteger[2];

        // IMPLEMENT THIS

        return primes;
    }
}
