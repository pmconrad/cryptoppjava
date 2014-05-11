/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.jca;

import de.quisquis.ec.Decrypter;
import de.quisquis.ec.ECFactory;
import de.quisquis.ec.Encrypter;
import de.quisquis.ec.Signer;
import de.quisquis.ec.Verifier;

import java.security.PrivateKey;
import java.security.PublicKey;

/** An ECFactory implementation making use of JCA-provided crypto
 *  implementations.
 *
 * @author Peter Conrad
 */
public class JcaFactory extends ECFactory {
    @Override
    public Signer getSigner(PrivateKey key) {
        return new JcaSigner(key);
    }

    @Override
    public Verifier getVerifier(PublicKey key) {
        return new JcaVerifier(key);
    }

    @Override
    public Encrypter getEncrypter(PublicKey key) {
        return new JcaEncrypter(key);
    }

    @Override
    public Decrypter getDecrypter(PrivateKey key) {
        return new JcaDecrypter(key);
    }
}
