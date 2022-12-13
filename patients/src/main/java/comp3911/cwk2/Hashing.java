package comp3911.cwk2;

import java.security.SecureRandom;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Hashing {
    
    public static String[] hashPassword(String password) {
            String vals[] = new String[2];
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-512");
                md.update(salt);
                byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
                String encodedHash = Base64.getEncoder().encodeToString(hashBytes);
                String encodedSalt = Base64.getEncoder().encodeToString(salt);
                vals[0] = encodedHash;
                vals[1] = encodedSalt;
                return vals;
            }
            catch(NoSuchAlgorithmException error) {
                return null;
            }
    }

    public static String hashPasswordWithSalt(String password, String encodedSalt) {
        try {
            byte[] salt = Base64.getDecoder().decode(encodedSalt);
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt);
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            String encodedHash = Base64.getEncoder().encodeToString(hashBytes);
            return encodedHash;
        }
        catch(NoSuchAlgorithmException error) {
            return null;
        }
    }

}