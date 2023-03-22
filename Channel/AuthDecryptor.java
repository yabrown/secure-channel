import java.nio.ByteBuffer;
import java.util.Arrays;

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
    boolean debug = false;
    // Class constants.
    public static final int KEY_SIZE_BYTES = AuthEncryptor.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = AuthEncryptor.NONCE_SIZE_BYTES;

    // Instance variables.
    // IMPLEMENT THIS
    byte[] key;

    public AuthDecryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;
        // IMPLEMENT THIS
        this.key = key;
    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce has been included in <in>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] authDecrypt(byte[] in) {
        // IMPLEMENT THIS
        PRGen prg = new PRGen(key);
        byte[] key1 = new byte[KEY_SIZE_BYTES];
        byte[] key2 = new byte[KEY_SIZE_BYTES];
        for (int i=0; i<key1.length; i++){
            key1[i] = (byte)prg.next(32);
            key2[i] = (byte)prg.next(32);
        }

        ByteBuffer inBuffer = ByteBuffer.wrap(in);
        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        byte[] macR = new byte[KEY_SIZE_BYTES];
        byte[] ciphertext = new byte[in.length-NONCE_SIZE_BYTES-KEY_SIZE_BYTES];
        inBuffer.get(ciphertext, 0, in.length-NONCE_SIZE_BYTES-KEY_SIZE_BYTES);
        inBuffer.get(macR, 0, KEY_SIZE_BYTES);
        inBuffer.get(nonce, 0, NONCE_SIZE_BYTES);


        //enc(k1, nonce, m)
        byte[] plaintext = new byte[ciphertext.length];
        StreamCipher stream = new StreamCipher(key1, nonce);
        stream.cryptBytes(ciphertext, 0, plaintext, 0, ciphertext.length);

        // create mac
        PRF prf = new PRF(key2);

        // mac(k2, nonce, ciphertext)
        byte[] cipherNonce = ByteBuffer.allocate(ciphertext.length+nonce.length).put(ciphertext).put(nonce).array();
        byte[] macC = prf.eval(cipherNonce);
        
        for(int i =0; i<macR.length; i++){
            if (macR[i] != macC[i]) return null;
        }

        if(debug){
            System.out.println("/********************* Auth Decrypt *************************/");
            System.out.println("Cipher: " + Arrays.toString(ciphertext));
            System.out.println("macR: " + Arrays.toString(macR));
            System.out.println("nonce: " + Arrays.toString(nonce));
            System.out.println("macC: " + Arrays.toString(macC));
            System.out.println("plaintext: " + Arrays.toString(plaintext));
            System.out.println("/********************* Auth Decrypt End *************************/");
        }
        return plaintext;

    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce used to encrypt the data is provided in <nonce>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] authDecrypt(byte[] in, byte[] nonce) {
        assert nonce != null && nonce.length == NONCE_SIZE_BYTES;
        // IMPLEMENT THIS
        // IMPLEMENT THIS
        PRGen prg = new PRGen(key);
        byte[] key1 = new byte[KEY_SIZE_BYTES];
        byte[] key2 = new byte[KEY_SIZE_BYTES];
        for (int i=0; i<key1.length; i++){
            key1[i] = (byte)prg.next(32);
            key2[i] = (byte)prg.next(32);
        }

        ByteBuffer inBuffer = ByteBuffer.wrap(in);
        byte[] macR = new byte[KEY_SIZE_BYTES];
        byte[] ciphertext = new byte[in.length-KEY_SIZE_BYTES];
        inBuffer.get(ciphertext, 0, in.length-KEY_SIZE_BYTES);
        inBuffer.get(macR, 0, KEY_SIZE_BYTES);

        //enc(k1, nonce, m)
        byte[] plaintext = new byte[ciphertext.length];
        StreamCipher stream = new StreamCipher(key1, nonce);
        stream.cryptBytes(ciphertext, 0, plaintext, 0, ciphertext.length);

        // create mac
        PRF prf = new PRF(key2);

        // mac(k2, nonce, ciphertext)
        byte[] cipherNonce = ByteBuffer.allocate(ciphertext.length+nonce.length).put(ciphertext).put(nonce).array();
        byte[] macC = prf.eval(cipherNonce);
        
        for(int i =0; i<macR.length; i++){
            if (macR[i] != macC[i]) return null;
        }

        return plaintext;
    }
}
