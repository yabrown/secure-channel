import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.management.RuntimeErrorException;
/***
 * This class represents a single RSA key that can perform the RSA encryption and signing algorithms discussed in
 * class. Note that some of the public methods would normally not be part of a production API, but we leave them
 * public for the sake of grading.
 */
public class RSAKey {
    private boolean debug = false;
    private BigInteger exponent;
    private BigInteger modulus;
    private int PADDING_SIZE = 16;

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
        // IMPLEMENT THIS
        int size = maxPlaintextLength()+1;      //give room for ff
        byte[] result = ByteBuffer.allocate(size).put(input).array();
        result[input.length] = (byte)0XFF;
        return result;
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
        // find padded byte
        int i=input.length-1;
        while(input[i] != -1) i--;

        // reconstruct array up to padding byte, exclusive
        byte[] result = new byte[i];
        for (int j=0; j<result.length; j++){
            result[j] = input[j];
        }

        return result;
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
        // allocate space
        int mk1Size = input.length+PADDING_SIZE;
        ByteBuffer m = ByteBuffer.wrap(input);   // gives you padded valid m
        ByteBuffer mk1 = ByteBuffer.allocate(mk1Size).put(m);
        ByteBuffer r = ByteBuffer.allocate(32);
        
        //generate random nonce r
        for (int i=0; i<PADDING_SIZE; i+=4){
            r.putInt(i,prgen.next(32));
        }
        
        // use to seed new prgen G
        PRGen G = new PRGen(r.array());
        ByteBuffer Gr = ByteBuffer.allocate(mk1Size);
        for (int i=0; i<(mk1Size-4); i+=4){
            Gr.putInt(i,G.next(32));
        }
        Gr.putInt(mk1Size-4,G.next(32)); //in case any bits left over

        //Gr xor mk1 = GrXorMk1
        byte[] GrXorMk1 = new byte[mk1Size];
        for (int i=0; i<GrXorMk1.length; i++){
            GrXorMk1[i] = (byte) (Gr.get(i)^mk1.get(i));
        }

        //get hash of GrXorMk1
        byte[] hash = new byte[PADDING_SIZE];
        ByteBuffer.wrap(HashFunction.computeHash(GrXorMk1)).get(hash, 0, PADDING_SIZE);
        byte[] hashXorR = new byte[PADDING_SIZE];
        for (int i=0; i<hashXorR.length; i++){
            hashXorR[i] = (byte) (hash[i]^r.get(i));
        }

        byte[] result = ByteBuffer.allocate(mk1Size+PADDING_SIZE).put(GrXorMk1).put(hashXorR).array();
        if(result.length != maxPlaintextLength()+PADDING_SIZE+PADDING_SIZE+1) throw new RuntimeException("wrong size");

        if(debug){
            System.out.println("*************************ENCODING*************************");
            System.out.println("mk1: "+ Arrays.toString(mk1.array()));
            System.out.println("Nonce: " + Arrays.toString(r.array()));
            System.out.println("Gr: " + Arrays.toString(Gr.array()));
            System.out.println("GrXorMk1: " + Arrays.toString(GrXorMk1));
            System.out.println("Hash: "+ Arrays.toString(hash));
            System.out.println("hashXorR: "+ Arrays.toString(hashXorR));
            System.out.println("Result: " + Arrays.toString(result));
            System.out.println("*************************END*************************");
        }

        return result;
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
        int mk1Size = input.length-PADDING_SIZE;
        byte[] x = new byte[input.length-PADDING_SIZE];
        byte[] y = new byte[PADDING_SIZE];
        ByteBuffer in = ByteBuffer.wrap(input);
        in.get(x);
        in.get(y);

        //get hash
        byte[] hash = new byte[PADDING_SIZE];
        ByteBuffer.wrap(HashFunction.computeHash(x)).get(hash, 0, PADDING_SIZE);

        //recover nonce
        byte[] r = new byte[32];
        for (int i=0; i<PADDING_SIZE; i++){
            r[i] = (byte) (hash[i]^y[i]);
        }

        //regenerate G and Gr
        ByteBuffer Gr = ByteBuffer.allocate(mk1Size);
        PRGen G = new PRGen(r);
        for (int i=0; i<mk1Size-4; i+=4){
            Gr.putInt(i, G.next(32));
        }
        Gr.putInt(mk1Size-4, G.next(32));


        byte[] m = new byte[mk1Size-PADDING_SIZE];
        for (int i=0; i<m.length; i++){
            m[i] = (byte)(Gr.get(i)^x[i]);
        }
        if(debug){
            System.out.println("*************************DECODE*******************");
            System.out.println("input: " + Arrays.toString(in.array()));
            System.out.println("X: "+Arrays.toString(x));
            System.out.println("Y: "+Arrays.toString(y));
            System.out.println("Hash: "+ Arrays.toString(hash));
            System.out.println("r: "+ Arrays.toString(r));
            System.out.println("Gr: "+ Arrays.toString(Gr.array()));
            System.out.println("result (m): "+ Arrays.toString(m));
            System.out.println("*************************End*******************");
        }

        return m;
    }

    public byte[] cipher(byte[] input){
        BigInteger cipherBig = HW2Util.bytesToBigInteger(input);
        BigInteger resultBig = cipherBig.modPow(exponent, modulus);
        byte[] result = HW2Util.bigIntegerToBytes(resultBig, ((resultBig.bitLength()-1)/8)+1);
        return result;
    }

    public byte[] decipher(byte[] input){
        BigInteger cipherBig = HW2Util.bytesToBigInteger(input);
        BigInteger resultBig = cipherBig.modPow(exponent, modulus);
        byte[] result = HW2Util.bigIntegerToBytes(resultBig, ((resultBig.bitLength()-1)/8)+1);
        return result;
    }
    /***
     * Get the largest N such that any plaintext of size N bytes can be encrypted with this key and padding/encoding.
     *
     * @return upper bound of plaintext length applicable for this key
     */
    public int maxPlaintextLength() {
        //IMPLEMENT THIS
        return ((modulus.bitLength()-1)/8)-PADDING_SIZE-PADDING_SIZE-1; //subtract to be one less, then for ff, then for k1 and k0
        //might be issue here, off by one
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
        byte[] padded = addPadding(plaintext);
        byte[] encoded = encodeOaep(padded, prgen);
        byte[] enciphered = cipher(encoded);

        if (debug){
            System.out.println("*************************ENCRYPT*******************");
            System.out.println("Input: " + Arrays.toString(plaintext));
            System.out.println("Padded: " + Arrays.toString(padded));
            System.out.println("Encoded: " + Arrays.toString(encoded));
            System.out.println("Enciphered: " + Arrays.toString(enciphered));
            System.out.println("*************************END*******************");
        }

        return enciphered;
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
        byte[] deciphered = decipher(ciphertext);
        byte[] decoded = decodeOaep(deciphered);
        byte[] depadded = removePadding(decoded);

        if(debug){
            System.out.println("*************************DECRYPT*******************");
            System.out.println("Input: " + Arrays.toString(ciphertext));
            System.out.println("Deciphered: " + Arrays.toString(deciphered));
            System.out.println("Decoded: " + Arrays.toString(decoded));
            System.out.println("Depadded: " + Arrays.toString(depadded));
            System.out.println("*************************END*******************");
        }

        return depadded;
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
        BigInteger hash = HW2Util.bytesToBigInteger(HashFunction.computeHash(message));
        BigInteger sigBig = hash.modPow(exponent, modulus);
        byte[] sig = HW2Util.bigIntegerToBytes(sigBig, ((sigBig.bitLength()-1)/8+1));

        return sig;
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
        byte[] hash = HashFunction.computeHash(message);
        BigInteger hashBig  = HW2Util.bytesToBigInteger(hash);
        BigInteger sigBig = HW2Util.bytesToBigInteger(signature);
        BigInteger cipheredSigBig = sigBig.modPow(exponent, modulus);
        boolean match = (cipheredSigBig.equals(hashBig));
        // IMPLEMENT THIS

        return match;
    }

    public static void main(String args[]){
        byte[] rand = ByteBuffer.allocate(32).putInt(108275648).array();
        PRGen prg = new PRGen(rand);
        RSAKeyPair rsa= new RSAKeyPair(prg, 500);
        RSAKey privateKey = rsa.getPrivateKey();
        RSAKey publicKey = rsa.getPublicKey();
        if(publicKey.debug){
        System.out.println("Public Exponent:" + publicKey.exponent);
        System.out.println("Private Exponent:" + privateKey.exponent);
        System.out.println("Private Modulus:" + publicKey.modulus);
        System.out.println("Public Modulus:" + privateKey.modulus);
        System.out.println("maxPlaintextLength: " +publicKey.maxPlaintextLength());
        }

        String plaintext = "Hey";
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] padded = publicKey.addPadding(plaintextBytes);
        if(publicKey.debug){
        System.out.println("plaintext " + Arrays.toString(plaintextBytes));
        System.out.println("padded " + Arrays.toString(padded));
        }

        plaintext = "Hwrfva";
        byte[] encoded = publicKey.encodeOaep(publicKey.addPadding(plaintext.getBytes()), prg);
        byte[] decoded = privateKey.decodeOaep(encoded);
        
        System.out.println("plaintext " + Arrays.toString(plaintextBytes));
        System.out.println("decoded " + Arrays.toString(decoded));
        //System.out.println("unpadded " + Arrays.toString(padded));
        

        byte[] encrypted = publicKey.encrypt(plaintextBytes, prg);
        byte[] decrypted = privateKey.decrypt(encrypted);
        if(publicKey.debug){
            System.out.println("plaintext " + Arrays.toString(plaintextBytes));
            System.out.println("decoded " + Arrays.toString(decrypted));
        }
    }
}
