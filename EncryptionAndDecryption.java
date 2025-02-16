import java.security.*;
import javax.crypto.Cipher;
import java.util.Base64;

public class RSAEncryptionUtil {

    // Generates an RSA key pair
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating RSA key pair", e);
        }
    }

    // Encrypts a message using the given public key
    public static String encrypt(String message, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Encryption error", e);
        }
    }

    // Decrypts a message using the given private key
    public static String decrypt(String encryptedMessage, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Decryption error", e);
        }
    }

    public static void main(String[] args) {
        KeyPair keyPair = generateKeyPair();
        String message = "This is a secret message!";

        System.out.println("Original Message: " + message);

        String encryptedMessage = encrypt(message, keyPair.getPublic());
        System.out.println("Encrypted Message: " + encryptedMessage);

        String decryptedMessage = decrypt(encryptedMessage, keyPair.getPrivate());
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}
