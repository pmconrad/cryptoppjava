/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec;

import de.quisquis.ec.impl.bc.BouncyFactory;

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
        return new BouncyFactory();
    }

    /** @param key the private key to use for creating signatures
     * @return a Signer implementation provided by this factory */
    public abstract Signer getSigner(PrivateKey key);

    /** @param key the public key to use for signature verification
     * @return a Verifier implementation provided by this factory */
    public abstract Verifier getVerifier(PublicKey key);

    /** @param priv our private key to use
     *  @param pub the public encryption key to use
     * @return an Encrypter implementation provided by this factory */
    public abstract Encrypter getEncrypter(PrivateKey priv, PublicKey pub);

    /** @param priv the decryption key to use
     *  @param pub the sender's public key
     * @return an Decrypter implementation provided by this factory */
    public abstract Decrypter getDecrypter(PrivateKey priv, PublicKey pub);

    /** @param curve the standardized curve for which the desired Generator is
     *               to produce keys
     *  @return an Generator implementation provided by this factory */
    public abstract Generator getGenerator(Curve curve);
}
