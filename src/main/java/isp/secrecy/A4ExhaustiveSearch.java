package isp.secrecy;

import fri.isp.Agent;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of the last three bytes,
 * have been set to 0.
 * <p>
 * A DES key is represented by 8 bytes, but only 56 bits affect encryption; the remaining
 * bits are parity bits. Varying the last three bytes produces 2^24 byte representations
 * but only 2^21 effective keys. Any equivalent key that correctly decrypts the ciphertext
 * is acceptable; it need not match the original key byte for byte.
 * <p>
 * In main(), generate a demonstration key with the stated restriction, encrypt the supplied
 * message with DES/ECB/PKCS5Padding, and call bruteForceKey(). Verify that the returned key
 * decrypts the ciphertext to the complete original message. Use UTF-8 for text conversion.
 * The search must use only its arguments and the stated key restriction, not the original key.
 * DES and ECB are used only for this teaching exercise, not as recommended encryption.
 * <p>
 * To manually specify a key, use {@link javax.crypto.spec.SecretKeySpec}.
 */
public class A4ExhaustiveSearch {

    private static final SecureRandom RNG = new SecureRandom();

    public static void main(String[] args) throws Exception {

        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

        // generate key
        final byte[] lastThree = new byte[3];
        RNG.nextBytes(lastThree);
        final byte[] k = ByteBuffer.allocate(8).put(new byte[5]).put(lastThree).array();
        final Key key = new SecretKeySpec(k, "DES");

        // encryption
        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] ct = encrypt.doFinal(pt);

        // check that the key decrypts
        final Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        decrypt.init(Cipher.DECRYPT_MODE, key);
        final byte[] ptTest = decrypt.doFinal(ct);
        // System.out.println(new String(ptTest, StandardCharsets.UTF_8));
        if (Arrays.equals(ptTest, pt)) {
            System.out.printf("Generated key: %s%n", Agent.hex(k));
        } else {
            System.out.println("Generated key fails");
        }

        byte[] bfk = bruteForceKey(ct, message);
        if (bfk == null) {
            System.out.println("Key not found");
            return;
        }

        // prove that bfk also decrypts
        decrypt.init(Cipher.DECRYPT_MODE,  new SecretKeySpec(bfk, "DES"));
        final byte[] bfkPt = decrypt.doFinal(ct);
        System.out.printf("[DECIPHERED MESSAGE]: %s%n", new String(bfkPt, StandardCharsets.UTF_8));
        if (Arrays.equals(bfkPt, pt)) {
            System.out.println("Brute force returns OK key");
        } else {
            System.out.println("Brute force key fails");
        }
    }

    /**
     * Recover an 8-byte representation of a key that decrypts ct to the known message.
     * Return null if no matching key exists within the restricted search space.
     */
    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
        final byte[] ptFirstBlock = Arrays.copyOfRange(pt, 0, 8);

        ByteBuffer bb = ByteBuffer.allocate(8);
        final Cipher decrypt = Cipher.getInstance("DES/ECB/NoPadding");
        final Cipher decryptFinal = Cipher.getInstance("DES/ECB/PKCS5Padding");

        for (int i = 0; i < 1 << 24; i++) {
            bb.putInt(4, i);
            Key key = new SecretKeySpec(bb.array(), "DES");

            decrypt.init(Cipher.DECRYPT_MODE, key);
            byte[] dtFirstBlock = decrypt.doFinal(ct, 0, 8);

            if (Arrays.equals(dtFirstBlock, ptFirstBlock)) {
                try {
                    decryptFinal.init(Cipher.DECRYPT_MODE, key);
                    byte[] fullDt = decryptFinal.doFinal(ct);

                    if (Arrays.equals(fullDt, pt)) {
                        System.out.printf("Found a key: %s %n", Agent.hex(bb.array()));
                        return bb.array();
                    }
                } catch (BadPaddingException ignored) {}
            }
        }
        return null;
    }
}
