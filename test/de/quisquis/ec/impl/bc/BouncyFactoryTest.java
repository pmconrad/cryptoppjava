/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.bc;

import de.quisquis.ec.Curve;
import de.quisquis.ec.Decrypter;
import de.quisquis.ec.ECFactory;
import de.quisquis.ec.Generator;
import de.quisquis.ec.Verifier;

import java.security.KeyPair;
import java.security.SignatureException;

import java.util.Random;

import org.bouncycastle.jce.spec.IESParameterSpec;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Peter Conrad
 */
public class BouncyFactoryTest {
    protected static ECFactory instance;
    protected static Random prng;
    protected static KeyPair keys, moreKeys;
    protected static IESParameterSpec params;

    @BeforeClass
    public static void setUpClass() {
        instance = new BouncyFactory();
        Generator generator = instance.getGenerator(Curve.P256R1);
        keys = generator.generate();
        moreKeys = generator.generate();
        prng = new Random(12345);
        params = new IESParameterSpec(new byte[0], new byte[0], 128);
    }

    @AfterClass
    public static void tearDownClass() {
        instance = null;
    }

    /**
     * Test of signature creation + verification of the Jca implementation.
     * @throws SignatureException if something goes wrong
     */
    @Test
    public void testSignVerify() throws SignatureException {
        System.out.println("SignVerify");
        byte message[] = new byte[299];
        prng.nextBytes(message);
        byte signature[] = instance.getSigner(keys.getPrivate()).sign(message);
        Verifier verifier = instance.getVerifier(keys.getPublic());
        assertTrue(verifier.verify(message, signature));

        assertFalse(instance.getVerifier(moreKeys.getPublic())
                            .verify(message, signature));

        message[1]++;
        assertFalse(verifier.verify(message, signature));
    }

    /**
     * Test of en-/decryption of the Jca implementation.
     */
    @Test
    public void testEncryptDecrypt() {
        System.out.println("EncryptDecrypt");
        byte plain[] = new byte[299];
        prng.nextBytes(plain);
        byte cipher[] = instance.getEncrypter(moreKeys.getPrivate(),
                                              keys.getPublic(), params)
                                .encrypt(plain);
        Decrypter decrypter = instance.getDecrypter(keys.getPrivate(),
                                                    moreKeys.getPublic(),
                                                    params);
        byte decrypted[] = decrypter.decrypt(cipher);
        assertArrayEquals(plain, decrypted);

        try {
            instance.getDecrypter(moreKeys.getPrivate(), moreKeys.getPublic(),
                                  params)
                    .decrypt(cipher);
            fail("Expected exception!");
        } catch (IllegalStateException expected) {}

        cipher[1]++;
        try {
            decrypter.decrypt(cipher);
            fail("Expected exception!");
        } catch (IllegalStateException expected) {}
    }
}
