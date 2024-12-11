import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class ReadConfig {
        private Properties config = new Properties();

    public ReadConfig(String configFile) throws IOException {
        FileInputStream file = new FileInputStream(configFile);
        config.load(file);
    }

    public String curve() {
        return config.getProperty("CURVE").trim();
    }

    public byte[] privateKey() {
        return hexStringToByteArray(config.getProperty("PRIVATEKEY").trim());
    }
    
    public byte[] publicKey() {
        return hexStringToByteArray(config.getProperty("PUBLICKEY").trim());
    }

    public byte[] publicKeyUser() {
        return hexStringToByteArray(config.getProperty("KPUBCLIENT").trim());
    }

    public String userId() {
        return config.getProperty("USERID").trim(); 
    }

    public byte[] getHPass() {
        return hexStringToByteArray(config.getProperty("H(PASSWORD)").trim());
    }

    public String salt() {
        return config.getProperty("SALT").trim();
    }


    public String getCipherSuit() {
        return config.getProperty("CONFIDENTIALITY").trim();
    }

    public byte[] getSymmetricKey() {
        return hexStringToByteArray(config.getProperty("SYMMETRIC_KEY").trim());
    }

    public int getSymmetricKeySize() {
        return Integer.parseInt(config.getProperty("SYMMETRIC_KEY_SIZE").trim());
    }
    
    public int getIVSize() {
        return Integer.parseInt(config.getProperty("IV Size").trim());
    }

    public byte[] getIV() {
        return hexStringToByteArray(config.getProperty("IV").trim());
    }
    
    public String getIntegrity() {
        return config.getProperty("INTEGRITY").trim();
    }

    public String getHashAlgorithm() {
        return config.getProperty("H").trim();
    }

    public String getMACAlgorithm() {
        return config.getProperty("MAC").trim();
    }

    public byte[] getMACKey() {
        return hexStringToByteArray(config.getProperty("MACKEY").trim());
    }

    public int getMACSize() {
        return Integer.parseInt(config.getProperty("MACKEY_SIZE").trim());
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

}
