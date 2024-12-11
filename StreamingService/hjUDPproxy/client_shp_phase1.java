import java.io.*;
import java.net.*;
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


public class client_shp_phase1 {

    private static ReadConfig readConfigClient;
    private static ReadConfig readConfigServer;
    private static ReadConfig readConfigCryptoFile;
    
    private String clientId;
    private static String password;
    private String request;
    private String udpPort;
        
            // Constructor to accept client ID
            public client_shp_phase1(String clientId, String password, String request, String udpPort) throws IOException {
                this.readConfigClient       = new ReadConfig("ClientECCKeyPair.txt");
                this.readConfigServer       = new ReadConfig("ServerECCPubKey.txt");
                Security.addProvider(new BouncyCastleProvider());
                this.clientId   = clientId;
                this.password   = password;
                this.request    = request;
                this.udpPort    = udpPort; 
        }
    
        // Method to start the connection
        public void startConnection(String hostname, int port) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, SignatureException {
            try (Socket socket = new Socket(hostname, port)) {
                System.out.println("Connected to the server as client: " + clientId);
    
                InputStream input = socket.getInputStream();
                OutputStream output = socket.getOutputStream();
                
                //ClientId WRITE
                output.write(toByteArray(clientId));
                output.flush();
                System.out.println("Client ID sent to the server.");
    
                //ReadNonces
                byte[][] nonces = readNonces(input);
                System.out.println("Nonces read from Server");
    
                //Send Message 3
                sendMessage3(output, nonces);
                System.out.println("Message 3 sent to the server");
                
                //Read Message 4 from Server
                byte[] message4FullSize = new byte[550];
                int trueSize = input.read(message4FullSize);
                byte[] message4TrueSize = new byte[trueSize];
                System.arraycopy(message4FullSize, 0, message4TrueSize, 0, trueSize);
                System.out.println("Message 4 received from Server");
                byte[] originalMessage = receiveMessage4(message4TrueSize);
                byte [] nonce5plus1 = downloadCyptoConfig(originalMessage);
                this.readConfigCryptoFile   = new ReadConfig("cryptoconfig.txt");
                
                //Send message 5 (sync message) for server
                byte[] message5 = message5(nonce5plus1);
                output.write(message5);
                output.flush();
                System.out.println("Message 5 (Sync Message) sent to Server");
               
                

                output.close();
            } catch (IOException error) {
                System.out.println("error: " + error.getMessage());
            }
        }
    
    
        private void sendMessage3(OutputStream output, byte[][] nonces ) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
            
            byte[] requestByte  = toByteArray(request);
            byte[] userIdByte   = toByteArray(clientId);
            byte[] nonce3plus1  = incrementNonce(nonces[2]);
            byte[] nonce4       = createNonce();
            byte[] udpPortByte  = toByteArray(udpPort);

            byte[] message      = joinInfo(requestByte, userIdByte, nonce3plus1, nonce4, udpPortByte);

            byte[] PBE          = pbeEncrypt(message);  // Size : 64bytes
            byte[] digitalSig   = digitalSig(PBE);      // Size : 70/71/72 bytes
            byte[] HMAC         = hmac(PBE);            // Size : 32bytes

            byte[] finalMessage = joinEncryptions(PBE, digitalSig, HMAC);

            output.write(finalMessage);
            output.flush();

        }

        private byte[] hmac(byte[] message) throws NoSuchAlgorithmException, InvalidKeyException{

            //Using as hMACkey the hash of the User password (same as in the PBE)
            byte[] passwordByte = toByteArray(password);
            MessageDigest hash = MessageDigest.getInstance("SHA256");
            hash.update(passwordByte);
            byte[] passwordHashed = hash.digest();


            //hMac encryptation
            Mac hMac = Mac.getInstance("HMacSHA256");
            SecretKey hMacKey = new SecretKeySpec(passwordHashed, "HMacSHA256");
            hMac.init(hMacKey);
            hMac.update(message);
            
            return hMac.doFinal();

        }


        private byte[] digitalSig(byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException{
            //Private key with PKCS#8 format (tested on lab4)
            PKCS8EncodedKeySpec key = new PKCS8EncodedKeySpec(readConfigClient.privateKey());
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC"); 
            PrivateKey privateKey = keyFactory.generatePrivate(key);

            Signature signature = Signature.getInstance("SHA256withECDSA", "BC");

            signature.initSign(privateKey, new SecureRandom());
            signature.update(message);

            byte[] sigBytes = signature.sign();

            return sigBytes;
        }

        private byte[] pbeEncrypt(byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{

            byte[] passwordByte = toByteArray(password);
            byte[] salt         = toByteArray("e268abbc5264f250fecdb1ddce14d8f1");
            int iterationCount  = 2048;

            //Hashing the Password
            MessageDigest hash = MessageDigest.getInstance("SHA256");
            hash.update(passwordByte);
            byte[] passwordHashed = hash.digest();
    
            //Creating the key using the Hashed password of the user
            PBEKeySpec pbeSpec          = new PBEKeySpec(toString(passwordHashed).toCharArray());
            SecretKeyFactory keyFact    = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
            Key sKey                    = keyFact.generateSecret(pbeSpec);

            //Cypher with the key generated by the user password 
            Cipher cEnc = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
            cEnc.init(Cipher.ENCRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));
            byte[] out = cEnc.doFinal(message);

            return out;

        }

        private static byte[] receiveMessage4(byte[] messageEncrypted) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException{
            ByteBuffer buffer = ByteBuffer.wrap(messageEncrypted);
            
            int PBELenght = buffer.getInt();
            byte[] PBE = new byte[PBELenght];
            buffer.get(PBE);

            int digitalSigLenght = buffer.getInt();
            byte[] digitalSig = new byte[digitalSigLenght];
            buffer.get(digitalSig);

            byte[] HMAC = new byte[32];
            buffer.get(HMAC);

            verifyHMAC(HMAC,PBE);

            verifyDigitalSig(digitalSig, PBE);

            byte[] coupledOriginalMessage = decryptPBE(PBE);
            
            return coupledOriginalMessage;
        }

        private static void verifyHMAC(byte[] HMAC, byte[] message) throws InvalidKeyException, NoSuchAlgorithmException{
        
            byte[] passwordByte = toByteArray(password);
            MessageDigest hash = MessageDigest.getInstance("SHA256");
            hash.update(passwordByte);
            byte[] passwordHashed = hash.digest();

            byte[] hashResult;
            Mac hMac = Mac.getInstance("HMacSHA256");
            SecretKey hMacKey = new SecretKeySpec(passwordHashed, "HMacSHA256");
            
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

            X509EncodedKeySpec key = new X509EncodedKeySpec(readConfigServer.publicKey());
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

            Cipher cipher = Cipher.getInstance("ECIES", "BC");

            PKCS8EncodedKeySpec key = new PKCS8EncodedKeySpec(readConfigClient.privateKey());
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC"); 
            PrivateKey privateKey = keyFactory.generatePrivate(key);

            cipher.init(Cipher.DECRYPT_MODE, privateKey);
    
            return cipher.doFinal(PBE);   
        }

        private static byte[] downloadCyptoConfig(byte[] message) throws IOException {

            ByteBuffer buffer = ByteBuffer.wrap(message);
            
            int requestLenght = buffer.getInt();
            byte[] request = new byte[requestLenght];
            buffer.get(request);

            byte[] nonce4plus1 = new byte[16];
            buffer.get(nonce4plus1);

            byte[] nonce5 = new byte[16];
            buffer.get(nonce5);

            int cryptoConfigLenght = buffer.getInt();
            byte[] cryptoConfig = new byte[cryptoConfigLenght];
            buffer.get(cryptoConfig);

            Files.write(Paths.get("cryptoconfig.txt"), cryptoConfig);

            return incrementNonce(nonce5);
        }

        private byte[] message5(byte[] nonce5plus1) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException{

            int totalLength = 2 + nonce5plus1.length;
            byte[] confirmation = toByteArray("GO");

            ByteBuffer buffer = ByteBuffer.allocate(totalLength);

            buffer.put(confirmation);

            buffer.put(nonce5plus1);

            byte[] message = buffer.array();

            byte[] messageEncrypted = messageEncryption(message);

            byte[] encryptionHash   = encryptionHash(messageEncrypted);

            totalLength = 4 + messageEncrypted.length + 4 + encryptionHash.length;
            
            ByteBuffer buffer2 = ByteBuffer.allocate(totalLength);

            buffer2.putInt(messageEncrypted.length);
            buffer2.put(messageEncrypted);

            buffer2.putInt(encryptionHash.length);
            buffer2.put(encryptionHash);

            return buffer2.array();
        }

        @SuppressWarnings("unlikely-arg-type")
        private static byte[] messageEncryption (byte[] message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {

            //Get cipherSuit and algorithm from the CipherSuit
        Cipher cipher       = Cipher.getInstance(readConfigCryptoFile.getCipherSuit());
        String algorithm    = readConfigCryptoFile.getCipherSuit().split("/")[0];
        String mode         = "NULL";
        byte[] encryptedData;

        if(readConfigCryptoFile.getCipherSuit().contains("/")){
            mode = readConfigCryptoFile.getCipherSuit().split("/")[1];
        }

        //Key related to the algorithm
        SecretKey key = new SecretKeySpec(readConfigCryptoFile.getSymmetricKey(), algorithm);

        if (readConfigCryptoFile.getIV().equals("NULL") && !"GCM".equals(mode)){
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encryptedData = cipher.doFinal(message);

        } else if(mode.equals("GCM")){
            //IV Generation
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);

            //GCM Inicialization
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            byte[] finalData = cipher.doFinal(message);
            //Packet with the IV and encrypted data
            encryptedData = join(iv, finalData);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(readConfigCryptoFile.getIV()));
                encryptedData = cipher.doFinal(message);
            }

            return encryptedData;
        }

        private static byte[] encryptionHash(byte[] message) throws NoSuchAlgorithmException, InvalidKeyException {

            Mac mac = Mac.getInstance(readConfigCryptoFile.getMACAlgorithm());
            SecretKey macKey = new SecretKeySpec(readConfigCryptoFile.getMACKey(), readConfigCryptoFile.getMACAlgorithm());
            mac.init(macKey);
  
            return mac.doFinal(message);
        }

        private byte[] joinInfo(byte[] requestByte, byte[] userIdByte, byte[] nonce3plus1, byte[] nonce4, byte[] udpPortByte) {
            
            int totalLength = 4 + requestByte.length + 4 + userIdByte.length + nonce3plus1.length + nonce4.length + 4 + udpPortByte.length;

            ByteBuffer buffer = ByteBuffer.allocate(totalLength);

            buffer.putInt(requestByte.length);  
            buffer.put(requestByte);            

            buffer.putInt(userIdByte.length);   
            buffer.put(userIdByte);             

            buffer.put(nonce3plus1);             
            buffer.put(nonce4);                  

            buffer.putInt(udpPortByte.length);   
            buffer.put(udpPortByte);    

            return buffer.array();
        }

        private static byte[] join(byte[] byte1, byte[] byte2) throws IOException {
            byte[] join = new byte[byte1.length + byte2.length];
            System.arraycopy(byte1, 0, join, 0, byte1.length);
            System.arraycopy(byte2, 0, join, byte1.length, byte2.length);
            return join;
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
    
        private byte[][] readNonces (InputStream input) throws IOException{
            byte[][] nonces = new byte[3][16];
    
            for (int i = 0; i < 3; i++) {
                input.read(nonces[i]);
            }
    
            return nonces;
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

        private static byte[] createNonce() {
            SecureRandom random = new SecureRandom();
            byte[] nonce = new byte[16];
            random.nextBytes(nonce);
            return nonce;
        }

        private byte[] joinEncryptions(byte[] PBE, byte[] digitalSig, byte[] HMAC) throws IOException {
            int totalLength = PBE.length + 4 + digitalSig.length + HMAC.length;

            ByteBuffer buffer = ByteBuffer.allocate(totalLength);

            buffer.put(PBE);            

            buffer.putInt(digitalSig.length);
            buffer.put(digitalSig);             
           
            buffer.put(HMAC);                  

            return buffer.array();
        }
}
