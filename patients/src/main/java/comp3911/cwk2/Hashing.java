import java.security.SecureRandom;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;

public class Hashing {
    
    public static String digestToHex(byte[] byteArray) { // https://stackoverflow.com/questions/332079/in-java-how-do-i-convert-a-byte-array-to-a-string-of-hex-digits-while-keeping-l
        BigInteger bi = new BigInteger(1, byteArray);
        return String.format("%0" + (byteArray.length << 1) + "X", bi);
    }

    public static byte[][] hashPassword(String password) {
            byte[][] vals = new byte[2][];
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-512");
                md.update(salt);
                byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
                vals[0] = hashBytes;
                vals[1] = salt;
                return vals;
            }
            catch(NoSuchAlgorithmException error) {
                return null;
            }
    }

    public static byte[] hashPasswordWithSalt(String password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt);
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return hashBytes;
        }
        catch(NoSuchAlgorithmException error) {
            return null;
        }
    }

    public static void main(String[] args) {
        byte[][] val = Hashing.hashPassword("wysiwyg0");
        System.out.println(val[0]);
        System.out.println(val[1]);

    }

}