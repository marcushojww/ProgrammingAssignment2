import java.util.Base64;

public class Base64Class {

    //Encryption
    public static String encode(byte[] byteMessage) throws Exception {

       return Base64.getEncoder().encodeToString(byteMessage);
    }   
    //Decryption of encoded String
    public static byte[] decode(String encodedMessage) throws Exception {

        return Base64.getDecoder().decode(encodedMessage);
    }
     
}
