import java.security.*;
import javax.crypto.Cipher;

public class RSA {

        //Encryption
        public static byte[] encrypt(byte[] message, Key key) throws Exception {

                // Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as encrypt mode, 
                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsaCipher.init(Cipher.ENCRYPT_MODE, key);

                // Encrypt message
                byte[] encryptedMessage = rsaCipher.doFinal(message);

                return encryptedMessage;
        }

        // Decryption
        public static byte[] decrypt(byte[] message, Key key) throws Exception {

                // Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as decrypt mode, 
                Cipher desCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                desCipher.init(Cipher.DECRYPT_MODE, key);

                // decrypt message
                byte[] decryptedMessage = desCipher.doFinal(message);
                

                return decryptedMessage;
        }

}