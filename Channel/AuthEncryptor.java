import java.net.CookieHandler;
import java.nio.ByteBuffer;

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
    // IMPLEMENT THIS
    private byte[] key;

    public AuthEncryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;

        // IMPLEMENT THIS
        this.key = key;

    }

    // Encrypts the contents of <in> so that its confidentiality and integrity are protected against those who do not
    //     know the key and nonce.
    // If <nonceIncluded> is true, then the nonce is included in plaintext with the output.
    // Returns a newly allocated byte[] containing the authenticated encryption of the input.
    public byte[] authEncrypt(byte[] in, byte[] nonce, boolean includeNonce) {

        assert nonce.length == NONCE_SIZE_BYTES;
        // IMPLEMENT THIS

        // get two keys
        PRGen prg = new PRGen(key);
        byte[] key1 = new byte[KEY_SIZE_BYTES];
        byte[] key2 = new byte[KEY_SIZE_BYTES];
        for (int i=0; i<key1.length; i++){
            key1[i] = (byte)prg.next(32);
            key2[i] = (byte)prg.next(32);
        }


        //enc(k1, nonce, m)
        byte[] ciphertext = new byte[in.length];
        StreamCipher stream = new StreamCipher(key1, nonce);
        stream.cryptBytes(in, 0, ciphertext, 0, in.length);

        // create mac
        PRF prf = new PRF(key2);

        //INCLUDE NONCE TODO
        byte[] cipherNonce = ByteBuffer.allocate(ciphertext.length+nonce.length).put(ciphertext).put(nonce).array();

        // mac(k2, nonce, ciphertext)
        byte[] mac = prf.eval(cipherNonce);

        ByteBuffer out;
        if(includeNonce){
            out = ByteBuffer.allocate(ciphertext.length+nonce.length+mac.length);
        }else{
            out = ByteBuffer.allocate(ciphertext.length+mac.length);
        }

        out.put(ciphertext).put(mac);
        if(includeNonce) out.put(nonce, 0, nonce.length);

        return out.array();

    }
}
