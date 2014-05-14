/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec;

import java.security.KeyPair;
import java.security.SignatureException;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import org.junit.AfterClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Peter Conrad
 */
public abstract class AbstractSpeedTest {
    private static final int KEYPAIRS     = 19;
    private static final int MESSAGES     = 197;
    private static final int MESSAGE_MIN  = 1;
    private static final int MESSAGE_MAX  = 3000;
    private static final int TEST_TIME_MS = 30000;

    protected static ECFactory instance;
    protected static Random prng;
    protected static KeyPair keys[] = new KeyPair[KEYPAIRS];
    protected static byte messages[][] = new byte[MESSAGES][];

    public static void setUpClass() {
        Generator generator = instance.getGenerator(Curve.P256R1);
        for (int i = 0; i < KEYPAIRS; i++) {
            keys[i] = generator.generate();
        }
        prng = new Random(12345);
        for (int i = 0; i < MESSAGES; i++) {
            messages[i] = new byte[MESSAGE_MIN + prng.nextInt(MESSAGE_MAX - MESSAGE_MIN + 1)];
            prng.nextBytes(messages[i]);
        }
    }

    @AfterClass
    public static void tearDownClass() {
        instance = null;
        prng = null;
        keys = null;
        messages = null;
    }

    private static abstract class SpeedTester {
        public void run() throws SignatureException {
            for (int i = 0; i < 10; i++) {
                runRound(i); // Warmup
            }
            final long start = System.currentTimeMillis();
            int counter = 0;
            long now;
            boolean stop = false;
            do {
                try {
                    runRound(counter++);
                } catch (ArrayIndexOutOfBoundsException e) {
                    stop = true;
                    counter--;
                }
                now = System.currentTimeMillis();
            } while (!stop && now < start + TEST_TIME_MS);
            System.out.println(counter + " rounds in " + (now - start) + "ms");
        }
        public abstract void runRound(int counter) throws SignatureException;
    }

    /**
     * Test of key pair creation of the Jca implementation.
     * @throws SignatureException if something goes wrong
     */
    @Test
    public void testGenerate() throws SignatureException {
        System.out.println("Generate");
        final Generator generator = instance.getGenerator(Curve.P256R1);
        final List<KeyPair> newKeys = new LinkedList<>();
        new SpeedTester() { @Override public void runRound(int counter) {
            newKeys.add(generator.generate());
        }}.run();
    }

    /**
     * Test of signature creation + verification of the Jca implementation.
     * @throws SignatureException if something goes wrong
     */
    @Test
    public void testSignVerify() throws SignatureException {
        System.out.println("Sign");
        final List<byte[]> signatures = new LinkedList<>();
        new SpeedTester() { @Override public void runRound(int counter) throws SignatureException {
            Signer signer = instance.getSigner(keys[counter % keys.length].getPrivate());
            signatures.add(signer.sign(messages[counter % messages.length]));
        }}.run();
        System.out.println("Verify");
        final Iterator<byte[]> signature = signatures.iterator();
        new SpeedTester() { @Override public void runRound(int counter) throws SignatureException {
            if (!signature.hasNext()) {
                throw new ArrayIndexOutOfBoundsException(-2);
            }
            Verifier verifier = instance.getVerifier(keys[counter % keys.length].getPublic());
            assertTrue(verifier.verify(messages[counter % messages.length],
                                       signature.next()));
        }}.run();
    }

    /**
     * Test of en-/decryption of the Jca implementation.
     * @throws SignatureException never
     */
    @Test
    public void testEncryptDecrypt() throws SignatureException {
        System.out.println("Encrypt");
        final List<byte[]> ciphers = new LinkedList<>();
        new SpeedTester() { @Override public void runRound(int counter) throws SignatureException {
            Encrypter encrypter = instance.getEncrypter(keys[counter % keys.length].getPrivate(),
                                                        keys[counter % keys.length].getPublic());
            ciphers.add(encrypter.encrypt(messages[counter % messages.length]));
        }}.run();
        System.out.println("Decrypt");
        final Iterator<byte[]> cipher = ciphers.iterator();
        new SpeedTester() { @Override public void runRound(int counter) throws SignatureException {
            if (!cipher.hasNext()) {
                throw new ArrayIndexOutOfBoundsException(-2);
            }
            Decrypter decrypter = instance.getDecrypter(keys[counter % keys.length].getPrivate(),
                                                        keys[counter % keys.length].getPublic());
            decrypter.decrypt(cipher.next());
        }}.run();
    }
}
