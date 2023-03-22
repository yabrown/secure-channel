import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;



public class Test {
    
    public static void main(String args[]){
        boolean verbose = false;

        byte[] rand = ByteBuffer.allocate(32).putInt(108275689).array();
        PRGen prg = new PRGen(rand);
        RSAKeyPair rsa= new RSAKeyPair(prg, 500);
        RSAKey privateKey = rsa.getPrivateKey();
        RSAKey publicKey = rsa.getPublicKey();

        if(verbose){
            System.out.println("Public Exponent:" + publicKey.getExponent());
            System.out.println("Private Exponent:" + privateKey.getExponent());
            System.out.println("Private Modulus:" + publicKey.getModulus());
            System.out.println("Public Modulus:" + privateKey.getModulus());
            System.out.println("maxPlaintextLength: " + publicKey.maxPlaintextLength());
        }
        /***********************************************************************************/
        //PADDING TESTS

        String text= "Hey";
        byte[] plaintext = text.getBytes();
        byte[] padded = publicKey.addPadding(plaintext);
        byte[] unpadded = privateKey.removePadding(padded);

        if (!Arrays.equals(plaintext, unpadded)){
            System.out.println("Padding problem: Hey... " + Arrays.toString(plaintext) + "-->" + Arrays.toString(unpadded));
        
         System.exit(1);}

        text= "";
        plaintext = text.getBytes();
        padded = publicKey.addPadding(plaintext);
        unpadded = privateKey.removePadding(padded);

        if (!Arrays.equals(plaintext, unpadded)){
            System.out.println("Padding problem: empty string... " + Arrays.toString(plaintext) + "-->" + Arrays.toString(unpadded));
       
        System.exit(1); }


        text= "ilajks;f0q";
        plaintext = text.getBytes();
        padded = publicKey.addPadding(plaintext);
        unpadded = privateKey.removePadding(padded);
        if (!Arrays.equals(plaintext, unpadded)){
            System.out.println("Padding problem: random... " + Arrays.toString(plaintext) + "-->" + Arrays.toString(unpadded));
        
         System.exit(1);}

        /***********************************************************************************/
        //cipher TESTS 

        text = "Hey";
        plaintext = text.getBytes();
        padded = publicKey.addPadding(plaintext);
        byte[] enciphered = publicKey.cipher(padded);
        byte[] deciphered = privateKey.decipher(enciphered);
        if (!Arrays.equals(padded, deciphered)){
            System.out.println("enciphering problem: hey... " + Arrays.toString(padded) + "-->" + Arrays.toString(deciphered));
        
         System.exit(1);}

         text = "";
        plaintext = text.getBytes();
        padded = publicKey.addPadding(plaintext);
        enciphered = publicKey.cipher(padded);
        deciphered = privateKey.decipher(enciphered);
        if (!Arrays.equals(padded, deciphered)){
            System.out.println("enciphering problem: hey... " + Arrays.toString(padded) + "-->" + Arrays.toString(deciphered));
        
         System.exit(1);}

         text = "asfvoienrg8q34";
        plaintext = text.getBytes();
        padded = publicKey.addPadding(plaintext);
        enciphered = publicKey.cipher(padded);
        deciphered = privateKey.decipher(enciphered);
        if (!Arrays.equals(padded, deciphered)){
            System.out.println("enciphering problem: hey... " + Arrays.toString(padded) + "-->" + Arrays.toString(deciphered));
        
         System.exit(1);}


        /***********************************************************************************/
        //encoding TESTS 

        text = "Hey";
        plaintext = text.getBytes();
        padded = publicKey.addPadding(plaintext);
        byte[] encoded = publicKey.encodeOaep(padded, prg);
        byte[] decoded = privateKey.decodeOaep(encoded);
        if (!Arrays.equals(padded, decoded)){
            System.out.println("encoding problem: hey... " + Arrays.toString(plaintext) + "-->" + Arrays.toString(decoded));
        
         System.exit(1);}

        text = "";
        plaintext = text.getBytes();
        padded = publicKey.addPadding(plaintext);
        encoded = publicKey.encodeOaep(padded, prg);
        decoded = privateKey.decodeOaep(encoded);
        if (!Arrays.equals(padded, decoded)){
            System.out.println("encoding problem: empty... " + Arrays.toString(plaintext) + "-->" + Arrays.toString(decoded));
        
         System.exit(1);}

        text = "asodij87 237q";
        plaintext = text.getBytes();
        padded = publicKey.addPadding(plaintext);
        encoded = publicKey.encodeOaep(padded, prg);
        decoded = privateKey.decodeOaep(encoded);
        if (!Arrays.equals(padded, decoded)){
            System.out.println("encoding problem: random... " + Arrays.toString(plaintext) + "-->" + Arrays.toString(decoded));
        
         System.exit(1);}
        /***********************************************************************************/

        //signing TESTS 

        text = "Hey";
        plaintext = text.getBytes();
        padded = publicKey.addPadding(plaintext);
        byte[] signed = privateKey.sign(padded, prg);

        if (!publicKey.verifySignature(padded, signed)){
            System.out.println("signing problem: hey ..." );
        
            System.exit(1);
        }
        text = "";
        plaintext = text.getBytes();
        padded = publicKey.addPadding(plaintext);
        signed = privateKey.sign(padded, prg);
        if (!publicKey.verifySignature(padded, signed)){
            System.out.println("signing problem: empty " );
        
         System.exit(1);}

        text = "asodij 8723";
        plaintext = text.getBytes();
        padded = publicKey.addPadding(plaintext);
        signed = privateKey.sign(padded, prg);
        if (!publicKey.verifySignature(padded, signed)){
            System.out.println("signing problem: random " );
        
         System.exit(1);}
        
        /***********************************************************************************/
        //encrypting TESTS 

        text = "Hey";
        plaintext = text.getBytes();
        byte[] encrypted = publicKey.encrypt(plaintext, prg);
        byte[] decrypted = privateKey.decrypt(encrypted);
        if (!Arrays.equals(plaintext, decrypted)){
            System.out.println("encrypting problem: hey... " + Arrays.toString(plaintext) + "-->" + Arrays.toString(decrypted));
            System.exit(1);
        }

        text = "";
        plaintext = text.getBytes();
        encrypted = publicKey.encrypt(plaintext, prg);
        decrypted = privateKey.decrypt(encrypted);
        if (!Arrays.equals(plaintext, decrypted)){
            System.out.println("encrypting problem: empty... " + Arrays.toString(plaintext) + "-->" + Arrays.toString(decrypted));
            System.exit(1);
        }

        text = "asodij87 237q";
        plaintext = text.getBytes();
        encrypted = publicKey.encrypt(plaintext, prg);
        decrypted = privateKey.decrypt(encrypted);
        if (!Arrays.equals(plaintext, decrypted)){
            System.out.println("encrypting problem: random... " + Arrays.toString(plaintext) + "-->" + Arrays.toString(decrypted));
            System.exit(1);
        }

        plaintext = new byte[publicKey.maxPlaintextLength()];
        encrypted = publicKey.encrypt(plaintext, prg);
        decrypted = privateKey.decrypt(encrypted);
        if (!Arrays.equals(plaintext, decrypted)){
            System.out.println("encrypting problem: random... " + Arrays.toString(plaintext) + "-->" + Arrays.toString(decrypted));
            System.exit(1);
        }
        /***********************************************************************************/
        //DHKE tests
        byte[] rand1 = ByteBuffer.allocate(32).putInt(981725790).array();
        PRGen prg1 = new PRGen(rand1);
        byte[] rand2 = ByteBuffer.allocate(32).putInt(375489111).array();
        PRGen prg2 = new PRGen(rand2);
        KeyExchange server = new KeyExchange(prg1, true);
        KeyExchange client = new KeyExchange(prg2, false);

        byte[] fromServer = server.prepareOutMessage();
        byte[] fromClient = client.prepareOutMessage();

        //test standard
        byte[] serverFinal = server.processInMessage(fromClient);
        byte[] clientFinal = client.processInMessage(fromServer);
            //test that equal
        if(!Arrays.equals(serverFinal, clientFinal)){
            System.out.println("DHKE problem (standard): serverFinal= " + Arrays.toString(serverFinal) + "; clientFinal= " + Arrays.toString(clientFinal));
            System.exit(1);
        }
            //test that not null
        if(serverFinal==null || clientFinal==null){
            System.out.println("DHKE problem (standard): shouldn't be null");
            System.exit(1);
        }

        //test invalid inputs
        byte[] one = HW2Util.bigIntegerToBytes(BigInteger.ONE, 1);
        byte[] pMinusOne = HW2Util.bigIntegerToBytes(DHConstants.p.subtract(BigInteger.ONE), 1024/8);
        serverFinal = server.processInMessage(one);
        clientFinal = client.processInMessage(pMinusOne);
            //test that both are null
        if(serverFinal != null){
            System.out.println("DHKE problem (invalid inputs): instead of null, serverFinal= " + Arrays.toString(serverFinal));
            System.exit(1);
        }
        if(clientFinal != null){
            System.out.println("DHKE problem (invalid inputs): instead of null, clientFinal= " + Arrays.toString(clientFinal));
            System.exit(1);
        }

        /***********************************************************************************/
        /***********************************************************************************/


        
    }
}
