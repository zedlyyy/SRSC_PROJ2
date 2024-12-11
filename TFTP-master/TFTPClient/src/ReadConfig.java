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