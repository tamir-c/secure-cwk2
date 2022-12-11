package comp3911.cwk2;

import java.security.SecureRandom;

import org.eclipse.jetty.server.handler.AbstractHandler.ErrorDispatchHandler;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class Hashing {
    
    public static String hashPassword(String password) {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-512");
                md.update(salt);
                byte[] hashedPasswordBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
                String hashedPassword = new String(hashedPasswordBytes, StandardCharsets.UTF_8);
                return hashedPassword;
            }
            catch(NoSuchAlgorithmException error) {
                return null;
            }
    }

}