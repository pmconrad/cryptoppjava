/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec;

import de.quisquis.ec.impl.KeyGenerator;

import de.quisquis.ec.impl.jca.JcaFactory;

import java.security.PrivateKey;
import java.security.PublicKey;

/** Provides an abstract entry point for implementations of ECDSA signature
 *  creation/verification and ECIES en-/decryption.
 *
 * @author Peter Conrad
 */
public abstract class ECFactory {
    protected ECFactory() {}

    /** @return the "best" available ECFactory */
    public static ECFactory getInstance() {
        return new JcaFactory();
    }

    /** @param key the private key to use for creating signatures
     * @return a Signer implementation provided by this factory */
    public abstract Signer getSigner(PrivateKey key);

    /** @param key the public key to use for signature verification
     * @return a Verifier implementation provided by this factory */
    public abstract Verifier getVerifier(PublicKey key);

    /** @param key the encryption key to use
     * @return an Encrypter implementation provided by this factory */
    public abstract Encrypter getEncrypter(PublicKey key);

    /** @param key the decryption key to use
     * @return an Decrypter implementation provided by this factory */
    public abstract Decrypter getDecrypter(PrivateKey key);

    /** @param curve the standardized curve for which the desired Generator is
     *               to produce keys
     *  @return an Generator implementation provided by this factory */
    public Generator getGenerator(Curve curve) {
        return new KeyGenerator(curve);
    }
}
