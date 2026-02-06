import java.math.BigInteger;

/***
 * This class represents a pair of RSA keys to be used for asymmetric encryption.
 */
public class RSAKeyPair {
    private RSAKey publicKey;
    private RSAKey privateKey;
    private BigInteger P;
    private BigInteger Q;

    private static final BigInteger E = BigInteger.valueOf(65537);
    private static final int PRIME_CERTAINTY = 80;
    /***
     * Create an RSA key pair.
     *
     * @param rand PRGen that this class can use to get pseudorandom bits
     * @param numBits size in bits of each of the primes that will be used
     */
    public RSAKeyPair(PRGen rand, int numBits) {
        if (rand == null) throw new NullPointerException();
        if (numBits < 2) throw new IllegalArgumentException("numBits too small");

        while (true) {

            P = new BigInteger(numBits, PRIME_CERTAINTY, rand);
            do {
                Q = new BigInteger(numBits, PRIME_CERTAINTY, rand);
            } while (P.equals(Q));

            BigInteger phi = (P.subtract(BigInteger.ONE)).multiply(Q.subtract(BigInteger.ONE));

            if (!E.gcd(phi).equals(BigInteger.ONE)) continue;

            BigInteger N = P.multiply(Q);
            BigInteger d = E.modInverse(phi);

            publicKey = new RSAKey(E, N);
            privateKey = new RSAKey(d, N);

            break;
        }

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
        return new BigInteger[]{P, Q};
    }
}
