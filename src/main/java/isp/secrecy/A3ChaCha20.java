package isp.secrecy;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, encrypt their messages
 * using the ChaCha20 stream cipher to provide confidentiality. Perform ten request-reply rounds:
 * Alice sends one encrypted message and Bob sends one encrypted reply in each round
 * (twenty encrypted messages in total). Both agents must decrypt and display received messages.
 * This exercise does not provide message authentication.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/ChaCha20ParameterSpec.html
 */
public class A3ChaCha20 {

    private static final SecureRandom RNG = new SecureRandom();

    public static void main(String[] args) throws Exception {

        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);


                for (int i = 0; i < 10; i++) {
                    // Sends a msg
                    final byte[] encryptedMsg = encrypt(key, pt, 1);
                    send("bob", encryptedMsg);

                    // Receives a msg
                    final byte[] received = receive("bob");

                    final byte[] dt = decrypt(key, received);
                    print("%s%n", new String(dt, StandardCharsets.UTF_8));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final String message = "Alice, take a chill pill. Bobby.";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                for (int i = 0; i < 10; i++) {
                    // Receive a msg
                    final byte[] received = receive("alice");

                    final byte[] dt = decrypt(key, received);
                    print("%s%n", new String(dt, StandardCharsets.UTF_8));

                    // Send a msg
                    final byte[] encryptedMsg = encrypt(key, pt, 5);
                    send("alice", encryptedMsg);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    private static byte[] encrypt(Key key, byte[] pt, int counter) throws Exception {

        byte[] nonce = new byte[12];
        RNG.nextBytes(nonce);

        final Cipher encrypt = Cipher.getInstance("ChaCha20");
        encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
        final byte[] ct = encrypt.doFinal(pt);

        return ByteBuffer.allocate(nonce.length + 4 + ct.length)
                .put(nonce).putInt(counter).put(ct).array();
    }

    private static byte[] decrypt(Key key, byte[] received) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(received);

        byte[] nonce = new byte[12];
        buf.get(nonce);

        int counter = buf.getInt();

        byte[] ct = new byte[buf.remaining()];
        buf.get(ct);

        System.out.printf("nonce=%s counter=%d ct=%s%n", Agent.hex(nonce), counter, Agent.hex(ct));

        final Cipher decrypt = Cipher.getInstance("ChaCha20");
        decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
        return decrypt.doFinal(ct);
    }
}
