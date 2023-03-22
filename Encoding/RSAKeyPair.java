import java.math.BigInteger;
import java.nio.ByteBuffer;

import javax.naming.Binding;
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

        BigInteger one = BigInteger.valueOf(1);
        BigInteger p = BigInteger.probablePrime(numBits, rand);
        BigInteger q = BigInteger.probablePrime(numBits, rand);
        BigInteger n = p.multiply(q);
        BigInteger totient = p.subtract(one).multiply(q.subtract(one));
        BigInteger e=BigInteger.valueOf(3);
        
        // find e, coprime with totient
        while(!(e.gcd(totient).equals(one))){
            e = BigInteger.probablePrime(numBits-2, rand);
            if (e.compareTo(totient) > 0){throw new RuntimeException("e exceeds n-- something went wrong");}
        };
        BigInteger d = e.modInverse(totient);

        privateKey = new RSAKey(d, n);
        publicKey = new RSAKey(e, n);

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
        primes[0] = this.p;
        primes[1] = this.q;

        return primes;
    }

    public static void main(String args[]){
        byte[] rand = ByteBuffer.allocate(32).putInt(1082756489).array();
        PRGen prg = new PRGen(rand);
        RSAKeyPair rsa= new RSAKeyPair(prg, 10);
    }
}
