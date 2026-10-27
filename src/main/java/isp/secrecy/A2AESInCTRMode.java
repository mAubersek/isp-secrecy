package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, encrypt their messages
 * using AES in counter mode to provide confidentiality. Perform ten request-reply rounds:
 * Alice sends one encrypted message and Bob sends one encrypted reply in each round
 * (twenty encrypted messages in total). Both agents must decrypt and display received messages.
 * This exercise does not provide message authentication.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/IvParameterSpec.html
 */
public class A2AESInCTRMode {
    public static void main(String[] args) throws Exception {

        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);


                for (int i = 0; i < 10; i++) {
                    // Sends a msg
                    final byte[] encryptedMsg = encrypt(key, pt);
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

                final String message = "Alice, take a chill pill.";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                for (int i = 0; i < 10; i++) {
                    // Receive a msg
                    final byte[] received = receive("alice");

                    final byte[] dt = decrypt(key, received);
                    print("%s%n", new String(dt, StandardCharsets.UTF_8));

                    // Send a msg
                    final byte[] encryptedMsg = encrypt(key, pt);
                    send("alice", encryptedMsg);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    private static byte[] encrypt(Key key, byte[] pt) throws Exception {
        final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
        encrypt.init(Cipher.ENCRYPT_MODE, key); // java generates iv
        final byte[] ct = encrypt.doFinal(pt);
        final byte[] iv = encrypt.getIV();

        return ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array();
    }

    private static byte[] decrypt(Key key, byte[] received) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(received);

        byte[] iv = new byte[16];
        buf.get(iv);

        byte[] ct = new byte[buf.remaining()];
        buf.get(ct);

        System.out.printf("IV=%s CT=%s%n", Agent.hex(iv), Agent.hex(ct));

        final Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding");
        decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return decrypt.doFinal(ct);
    }
}
