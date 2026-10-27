package isp.secrecy;

import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import fri.isp.Agent;

/**
 * EXERCISE:
 * - Study the example
 * - Test different ciphers
 *
 * RC4 is used here to keep the introductory example simple: initialization requires
 * only a key, with no IV or nonce. RC4 is obsolete and insecure and must not be used
 * in new applications; this example demonstrates API usage, not recommended cryptography.
 * When testing other ciphers, adapt the key type and cipher parameters as needed.
 *
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 */
public class SymmetricCipherExample {
    public static void main(String[] args) throws Exception {
        final String message = "Hi Bob, this is Alice.";
        System.out.println("[MESSAGE] " + message);

        // STEP 1: Alice and Bob agree upon a cipher and a shared secret key
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
        System.out.println("[PT] " + Agent.hex(pt));

        //  STEP 2: Create a cipher, encrypt the PT and, optionally, extract cipher parameters (such as IV)
        final Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, key); // iv should be a parameter - java will generate a secure iv
        final byte[] cipherText = encrypt.doFinal(pt);
        final byte[] iv = encrypt.getIV();

        // STEP 3: Print out cipher text (in HEX) [this is what an attacker would see]
        System.out.println("[IV] " + Agent.hex(iv));
        System.out.println("[CT] " + Agent.hex(cipherText));

        /*
         * STEP 4.
         * The receiver creates a Cipher object, defines the algorithm, the secret key and
         * possibly additional parameters (such as IV), and then decrypts the cipher text
         */
        final Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        final byte[] dt = decrypt.doFinal(cipherText);
        System.out.println("[PT] " + Agent.hex(dt));

        // Todo: What happens if the key is incorrect? (Try with RC4 or AES in CTR mode)

        // STEP 5: Create a string from a byte array
        System.out.println("[MESSAGE] " + new String(dt, StandardCharsets.UTF_8));
    }
}
