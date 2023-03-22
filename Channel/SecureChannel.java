import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class SecureChannel extends InsecureChannel {
    // This is just like an InsecureChannel, except that it provides 
    //    authenticated encryption for the messages that pass
    //    over the channel.   It also guarantees that messages are delivered 
    //    on the receiving end in the same order they were sent (returning
    //    null otherwise).  Also, when the channel is first set up,
    //    the client authenticates the server's identity, and the necessary
    //    steps are taken to detect any man-in-the-middle (and to close the
    //    connection if a MITM is detected).
    //
    // The code provided here is not secure --- all it does is pass through
    //    calls to the underlying InsecureChannel.

    AuthEncryptor enc;
    AuthDecryptor dec;
    long nonceR;
    long nonceS;

    public SecureChannel(InputStream inStr, OutputStream outStr,
                         PRGen rand, boolean iAmServer,
                         RSAKey serverKey) throws IOException {
        // if iAmServer==false, then serverKey is the server's *public* key
        // if iAmServer==true, then serverKey is the server's *private* key

        super(inStr, outStr);
        // IMPLEMENT THIS
        nonceR = 0;
        nonceS = 0;
        byte[] encryptKey = new byte[AuthDecryptor.KEY_SIZE_BYTES];
        byte[] decryptKey = new byte[AuthDecryptor.KEY_SIZE_BYTES];

        /// DHKE key exchange
        if(iAmServer){
            //exchange-- make sure opposite order from server
            KeyExchange exchange = new KeyExchange(rand, iAmServer);
            super.sendMessage(exchange.prepareOutMessage());
            byte[] sessionKey = exchange.processInMessage(super.receiveMessage());
            PRGen prg = new PRGen(sessionKey);

            //split into two keys
            prg.nextBytes(encryptKey);
            prg.nextBytes(decryptKey);
            enc = new AuthEncryptor(encryptKey);
            dec = new AuthDecryptor(decryptKey);

            //sign to authenticate
            byte[] signature = serverKey.sign(sessionKey, rand);
            sendMessage(signature);
            
        }else{
            //exchange-- make sure opposite order from server
            KeyExchange exchange = new KeyExchange(rand, iAmServer);
            byte[] sessionKey = exchange.processInMessage(super.receiveMessage());
            super.sendMessage(exchange.prepareOutMessage());
            PRGen prg = new PRGen(sessionKey);

            //split into two keys
            prg.nextBytes(decryptKey);
            prg.nextBytes(encryptKey);
            enc = new AuthEncryptor(encryptKey);
            dec = new AuthDecryptor(decryptKey);

            // authenticate
            byte[] signatureR = receiveMessage();
            if(! serverKey.verifySignature(sessionKey, signatureR)){
                enc = null;
                dec = null;
                nonceR = 0;
                nonceS = 0;
                close();
            };
        }

        // verify authenticity

// reference is 40 lines
   }

    public void sendMessage(byte[] message) throws IOException {
        // IMPLEMENT THIS

        byte[] nonceArr = ByteBuffer.allocate(AuthEncryptor.NONCE_SIZE_BYTES).putLong(nonceS).array();
        byte[] encrypted = enc.authEncrypt(message, nonceArr, false);
        super.sendMessage(encrypted);
        nonceS++;
    }

    public byte[] receiveMessage() throws IOException {
        // IMPLEMENT THIS
        byte[] nonceArr = ByteBuffer.allocate(AuthEncryptor.NONCE_SIZE_BYTES).putLong(nonceR).array();
        byte[] decrypted = dec.authDecrypt(super.receiveMessage(), nonceArr);
        nonceR++;
        return decrypted;
    }
}
