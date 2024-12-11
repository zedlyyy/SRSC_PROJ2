import java.io.*;
import java.net.*;

import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class server_shp_phase1 {

    private int port = 12345; // Define the port number
    private static ReadConfig readConfigUserDataBase;
    private static ReadConfig readConfigServer;
    private static ReadConfig readConfigCryptoFile;
    private static String UDPPort;
    private static String clientRequest;

            public server_shp_phase1() throws IOException {
                this.readConfigUserDataBase     = new ReadConfig("userdatabase.txt");
                this.readConfigServer           = new ReadConfig("ServerECCKeyPair.txt");
                this.readConfigCryptoFile       = new ReadConfig("cryptoconfig.txt");
                this.UDPPort                    = "";
                this.clientRequest              = "";
                Security.addProvider(new BouncyCastleProvider());
        }


        public String[] startConnection() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server is listening on port " + port);

            while(true) {

                Socket socket = serverSocket.accept();
                System.out.println("Client connected.");

                InputStream input = socket.getInputStream();
                OutputStream output = socket.getOutputStream();

                //ClientID READ
                byte[] clientIdBytes = new byte[320];
                input.read(clientIdBytes);
                String clientId = toString(clientIdBytes);

                System.out.println("Client: " + clientId);

                //Generate 3 nonces and send them
                sendNonces(output);
                System.out.println("Nonces wrote for Client");

                //Receive Message 3 from client
                byte[] message3FullSize = new byte[200];
                int trueSize = input.read(message3FullSize);
                byte[] message3TrueSize = new byte[trueSize];
                System.arraycopy(message3FullSize, 0, message3TrueSize, 0, trueSize);
                byte[] originalMessage3 = receiveMessage3(message3TrueSize);
                System.out.println("Message 3 received from Client: " + clientId);

                //Send Message 4 to client
                byte[] message4 = deserializeDataAndMessage4(originalMessage3);
                output.write(message4);
                System.out.println("Message 4 sent to Client: " + clientId);

                //Receive Sync message from Client
                byte[] message5FullSize = new byte[500];
                trueSize = input.read(message5FullSize);
                byte[] message5TrueSize = new byte[trueSize];
                System.arraycopy(message5FullSize, 0, message5TrueSize, 0, trueSize);
                System.out.println("Message 5 received from Client: " + clientId);
                verifyMessage5(message5TrueSize);

                socket.close();
                break;
            }

        } catch (IOException ex) {
            System.out.println("Server exception: " + ex.getMessage());
            ex.printStackTrace();
        }

        String[] finalResponse = {clientRequest, UDPPort};     
        return finalResponse;
        
    }



    private static byte[] receiveMessage3(byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException{

        //Deserialize the message3 received from the client
        ByteBuffer buffer = ByteBuffer.wrap(message);

        byte[] PBE = new byte[80];
        buffer.get(PBE);

        int digitalSigLenght = buffer.getInt();
        byte[] digitalSig = new byte[digitalSigLenght];
        buffer.get(digitalSig);

        byte[] HMAC = new byte[32];
        buffer.get(HMAC);

        //First the Integrity verification
        //Second the Authentacity verification
        //Third the Confidentiality  
        verifyHMAC(HMAC, PBE);
     
        verifyDigitalSig(digitalSig, PBE);

        byte[] coupledOriginalMessage = decryptPBE(PBE);

        
        return coupledOriginalMessage;

    }

    private static void verifyHMAC(byte[] HMAC, byte[] message) throws InvalidKeyException, NoSuchAlgorithmException{
        
        byte[] hashResult;
        Mac hMac = Mac.getInstance("HMacSHA256");
        SecretKey hMacKey = new SecretKeySpec(readConfigUserDataBase.getHPass(), "HMacSHA256");
      
        hMac.init(hMacKey);
        hMac.update(message);
        hashResult = hMac.doFinal();
        

        //Checking Integrity
        if(!Arrays.equals(HMAC, hashResult)){
            System.out.println("Hashes diferentes !!");
            System.exit(1);
        } else {
            System.out.println("Hashes são iguais :) ");
        }
    }

    private static void verifyDigitalSig(byte[] digitalSig, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException, InvalidKeySpecException{

        X509EncodedKeySpec key = new X509EncodedKeySpec(readConfigUserDataBase.publicKeyUser());
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC"); 
        PublicKey publicKey = keyFactory.generatePublic(key);

        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");

        signature.initVerify(publicKey);
        signature.update(message);


        if (signature.verify(digitalSig)) {
            System.out.println("Assinatura reconhecida");
        } else {
            System.out.println("Assinatura não reconhecida");
            System.exit(1);
        }
    }

    private static byte[] decryptPBE(byte[] PBE) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException{

        int iterationCount  = 2048;
        byte[] salt = toByteArray(readConfigUserDataBase.salt());

        PBEKeySpec pbeSpec          = new PBEKeySpec(toString(readConfigUserDataBase.getHPass()).toCharArray());
        SecretKeyFactory keyFact    = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
        Key sKey                    = keyFact.generateSecret(pbeSpec);

        Cipher cDec                 = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
        cDec.init(Cipher.DECRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));

        byte[] out = cDec.doFinal(PBE);
        return out;   
    }

    private static byte[] deserializeDataAndMessage4(byte[] originalData) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        ByteBuffer buffer = ByteBuffer.wrap(originalData);

        int requestLenght = buffer.getInt();
        byte[] requestByte = new byte[requestLenght];
        buffer.get(requestByte);
        String request = toString(requestByte);

        clientRequest = request;

        int userLenght = buffer.getInt();
        byte[] userByte = new byte[userLenght];
        buffer.get(userByte);
        String userId = toString(userByte);

        byte[] nonce3Plus1 = new byte[16];
        buffer.get(nonce3Plus1);
    
        byte[] nonce4 = new byte[16];
        buffer.get(nonce4);

        int udpPortlenght = buffer.getInt();
        byte[] udpPortByte = new byte[udpPortlenght];
        buffer.get(udpPortByte);
        String udpPort = toString(udpPortByte);

        UDPPort = udpPort;

        return message4(request, userId, nonce3Plus1, nonce4, udpPort);
    }


    private static byte[] message4(String request, String userId, byte[] nonce3Plus1, byte[] nonce4, String udpPort) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, SignatureException{
        
        byte[] nonce4plus1          = incrementNonce(nonce4);
        byte[] nonce5               = createNonce();
        byte[] cryptoConfig         = Files.readAllBytes(Paths.get("cryptoconfig.txt"));
        byte[] messageSerialized    = messageSerialize(request, nonce4plus1, nonce5, cryptoConfig);

        byte[] publicEncryption = publicEncryption(messageSerialized);
        byte[] digitalSig       = digitalSig(publicEncryption);
        byte[] HMAC             = HMAC(publicEncryption);

        byte[] finalMessage     = joinEncryptions(publicEncryption, digitalSig, HMAC);

        return finalMessage;
    }

    private static byte[] messageSerialize(String request, byte[] nonce4plus1, byte[] nonce5, byte[] cryptoConfig) {
        //Serialization of the message
        byte[] requestByte = toByteArray(request);

        int totalLength = 4 + requestByte.length + nonce4plus1.length + nonce5.length + 4 + cryptoConfig.length;
        ByteBuffer buffer = ByteBuffer.allocate(totalLength);

        buffer.putInt(requestByte.length);
        buffer.put(requestByte);

        buffer.put(nonce4plus1);

        buffer.put(nonce5);

        buffer.putInt(cryptoConfig.length);
        buffer.put(cryptoConfig);

        return buffer.array();
    }

    private static byte[] publicEncryption(byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{       
        Cipher cipher = Cipher.getInstance("ECIES", "BC");

        X509EncodedKeySpec key = new X509EncodedKeySpec(readConfigUserDataBase.publicKeyUser());
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC"); 
        PublicKey publicKey = keyFactory.generatePublic(key);

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(message);
    }

    private static byte[] digitalSig(byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {


        //Digital Signature
        PKCS8EncodedKeySpec key = new PKCS8EncodedKeySpec(readConfigServer.privateKey());
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC"); 
        PrivateKey privateKey = keyFactory.generatePrivate(key);

        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");

        signature.initSign(privateKey, new SecureRandom());
        signature.update(message);

        byte[] sigBytes = signature.sign();

        return sigBytes;

    }

    private static byte[] HMAC (byte[] message) throws NoSuchAlgorithmException, InvalidKeyException {

        //hMac encryptation
        Mac hMac = Mac.getInstance("HMacSHA256");
        SecretKey hMacKey = new SecretKeySpec(readConfigUserDataBase.getHPass(), "HMacSHA256");
        hMac.init(hMacKey);
        hMac.update(message);
            
        return hMac.doFinal();
    }

    private static byte[] joinEncryptions(byte[] publicEncryption, byte[] digitalSig, byte[] HMAC) throws IOException {
        int totalLength = 4 + publicEncryption.length + 4 + digitalSig.length + HMAC.length;

        ByteBuffer buffer = ByteBuffer.allocate(totalLength);

        buffer.putInt(publicEncryption.length);
        buffer.put(publicEncryption);            

        buffer.putInt(digitalSig.length);   
        buffer.put(digitalSig);             
       
        buffer.put(HMAC);                  

        return buffer.array();
    }


    private static void verifyMessage5(byte[] message) throws InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException{

        ByteBuffer buffer = ByteBuffer.wrap(message);

        int encriptionLenght = buffer.getInt();
        byte[] encription = new byte[encriptionLenght];
        buffer.get(encription);

        int hashLenght = buffer.getInt();
        byte[] hash = new byte[hashLenght];
        buffer.get(hash);

        verifyHash(hash, encription);
        byte[] syncMessage = verifyEncription(encription);

        ByteBuffer buffer2 = ByteBuffer.wrap(syncMessage);

        byte[] sync = new byte[2];
        buffer2.get(sync);
        String syncMessageString = toString(sync);

        byte[] nonce5plus1 = new byte[16];
        buffer2.get(nonce5plus1);

        if(syncMessageString.equals("GO")){
            System.out.println("Handshake completed !");
        } else {
            System.out.println("Something went wrong !");
            System.exit(1);
        }
        
    }

    private static void verifyHash(byte[] hash, byte[] encription) throws InvalidKeyException, NoSuchAlgorithmException {

        Mac mac = Mac.getInstance(readConfigCryptoFile.getMACAlgorithm());
        SecretKey macKey = new SecretKeySpec(readConfigCryptoFile.getMACKey(), readConfigCryptoFile.getMACAlgorithm());
        mac.init(macKey);
        byte[] hashCalculated = mac.doFinal(encription);

        if(!Arrays.equals(hash, hashCalculated)){
            System.out.println("Hashes diferentes !!");
            System.exit(1);
        } else {
            System.out.println("Hashes são iguais :) ");
        }

    }

    private static byte[] verifyEncription(byte[] encription) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException{

        Cipher cipher       = Cipher.getInstance(readConfigCryptoFile.getCipherSuit());
        String algorithm    = readConfigCryptoFile.getCipherSuit().split("/")[0];
        String mode         = "NULL";
        byte[] decryptedData;

        if(readConfigCryptoFile.getCipherSuit().contains("/")){
            mode = readConfigCryptoFile.getCipherSuit().split("/")[1];
        }

        //Key related to the algorithm
        SecretKey key = new SecretKeySpec(readConfigCryptoFile.getSymmetricKey(), algorithm);
        if (readConfigCryptoFile.getIV().equals("NULL") && !"GCM".equals(mode)){
            cipher.init(Cipher.DECRYPT_MODE, key);
            decryptedData = cipher.doFinal(encription);

        } else if(mode.equals("GCM")){
            byte[] iv = Arrays.copyOfRange(encription, 0, 12);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);


            //Packet without the IV
            //System.out.println(Utils.toString(iv));
            byte[] noIvData = Arrays.copyOfRange(encription, 12, encription.length );

            decryptedData   = cipher.doFinal(noIvData);

        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(readConfigCryptoFile.getIV()));
            decryptedData = cipher.doFinal(encription);
        }

        return decryptedData;
    }

    //Generate nonce 128 bit
    private static byte[] createNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);
        return nonce;
    }

    private static byte[] incrementNonce(byte[] nonce) {

        for (int i = nonce.length - 1; i >= 0; i--) {
            nonce[i]++; 
            if (nonce[i] != 0) {
                break;
            }
        }

        return nonce;
    }

    private static void sendNonces(OutputStream output) throws IOException {

        byte[] nonce1 = createNonce();
        byte[] nonce2 = createNonce();
        byte[] nonce3 = createNonce();
        output.write(nonce1);
        output.flush();
        output.write(nonce2);
        output.flush();
        output.write(nonce3);
        output.flush();
    }

    private static String toString(byte[] bytes, int length) {
        char[]	chars = new char[length];
        
        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(bytes[i] & 0xff);
        }
        
        return new String(chars);
    }
    
    private static String toString(byte[] bytes) {
        return toString(bytes, bytes.length);
    }
    
    private static byte[] toByteArray(String string) {
        byte[]	bytes = new byte[string.length()];
        char[]  chars = string.toCharArray();
        
        for (int i = 0; i != chars.length; i++)
        {
            bytes[i] = (byte)chars[i];
        }
        
        return bytes;
    }
}
