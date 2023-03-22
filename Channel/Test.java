import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Arrays;

public class Test {

    public static void main(String[] args){
        boolean debug = true;
    //////////////////////////// Unit Tests ////////////////////////////

        //unit test
        byte[] nonce = new byte[8];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(nonce);
        if(debug) System.out.println("Nonce: " + Arrays.toString(nonce));

        String text = "Hey";
        byte[] plaintext = text.getBytes();
        AuthEncryptor enc = new AuthEncryptor(nonce);
        AuthDecryptor dec = new AuthDecryptor(nonce); 
        byte[] cmn = enc.authEncrypt(plaintext, nonce, true);
        if(debug) System.out.println("Encrypted: " + Arrays.toString(cmn));
        byte[] p = dec.authDecrypt(cmn);

        
        if (!Arrays.equals(p, plaintext)){
            System.out.println("Basic Enc/Dec" + Arrays.toString(plaintext) + "-->" + Arrays.toString(p));
        
         System.exit(1);
        }

        cmn = enc.authEncrypt(plaintext, nonce, false);
        p = dec.authDecrypt(cmn, nonce);
        if (!Arrays.equals(p, plaintext)){
            System.out.println("Basic Enc/Dec:");
            System.out.println("Nonce: " + Arrays.toString(nonce));
            System.out.println("Plaintext: " + Arrays.toString(plaintext));
            System.out.println("Result: " + Arrays.toString(p));
            System.exit(1);
        }


    //////////////////////////// Stress Tests ////////////////////////////

        for (int i = 0; i<400; i++){
            nonce = new byte[8];
            rand.nextBytes(nonce);

            plaintext = new byte[(int)(Math.random()*1000)];
            rand.nextBytes(plaintext);
            enc = new AuthEncryptor(nonce);
            dec = new AuthDecryptor(nonce); 
            cmn = enc.authEncrypt(plaintext, nonce, true);
            p = dec.authDecrypt(cmn);

            if (!Arrays.equals(p, plaintext)){
                System.out.println("Basic Enc/Dec:");
                System.out.println("Nonce: " + Arrays.toString(nonce));
                System.out.println("Plaintext: " + Arrays.toString(plaintext));
                System.out.println("Result: " + Arrays.toString(p));
                System.exit(1);
            }

            cmn = enc.authEncrypt(plaintext, nonce, false);
            p = dec.authDecrypt(cmn, nonce);

            if (!Arrays.equals(p, plaintext)){
                System.out.println("Basic Enc/Dec:");
                System.out.println("Nonce: " + Arrays.toString(nonce));
                System.out.println("Plaintext: " + Arrays.toString(plaintext));
                System.out.println("Result: " + Arrays.toString(p));
                System.exit(1);
            }

        }

    }

}
