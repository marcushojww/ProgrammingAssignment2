import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import javax.crypto.*;
import java.util.Base64;
import java.security.Key;
import javax.crypto.Cipher;

public class AES {

        //Encryption
        public static byte[] encrypt(byte[] byteArray, Key key) throws Exception{

    
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte [] encryptedBytesArray = cipher.doFinal(byteArray);
                
                return encryptedBytesArray;
        }

        // AES decrypt
        public static byte[] decrypt(byte[] byteArray, Key key) throws Exception{
                
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte [] decryptedBytesArray = cipher.doFinal(byteArray);
                
                return decryptedBytesArray;
        }
}
