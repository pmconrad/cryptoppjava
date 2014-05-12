/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.bc;

import de.quisquis.ec.Curve;
import de.quisquis.ec.Decrypter;
import de.quisquis.ec.ECFactory;
import de.quisquis.ec.Encrypter;
import de.quisquis.ec.Generator;
import de.quisquis.ec.Signer;
import de.quisquis.ec.Verifier;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** An ECFactory implementation making use of JCA-provided crypto
 *  implementations.
 *
 * @author Peter Conrad
 */
public class BouncyFactory extends ECFactory {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public Signer getSigner(PrivateKey key) {
        return new BouncySigner(key);
    }

    @Override
    public Verifier getVerifier(PublicKey key) {
        return new BouncyVerifier(key);
    }

    @Override
    public Encrypter getEncrypter(PrivateKey priv, PublicKey pub,
                                  AlgorithmParameterSpec params) {
        return new BouncyEncrypter(priv, pub, params);
    }

    @Override
    public Decrypter getDecrypter(PrivateKey priv, PublicKey pub,
                                  AlgorithmParameterSpec params) {
        return new BouncyDecrypter(priv, pub, params);
    }

    @Override
    public Generator getGenerator(Curve curve) {
        return new BouncyGenerator(curve);
    }
}
