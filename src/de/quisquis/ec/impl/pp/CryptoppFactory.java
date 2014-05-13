/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.pp;

import de.quisquis.ec.Curve;
import de.quisquis.ec.Decrypter;
import de.quisquis.ec.ECFactory;
import de.quisquis.ec.Encrypter;
import de.quisquis.ec.Generator;
import de.quisquis.ec.Signer;
import de.quisquis.ec.Verifier;

import java.security.PrivateKey;
import java.security.PublicKey;

/** An ECFactory implementation making use of JCA-provided crypto
 *  implementations.
 *
 * @author Peter Conrad
 */
public class CryptoppFactory extends ECFactory {
    public static final boolean IS_USABLE;

    static {
        boolean usable = false;
        /*
        try {
            System.loadLibrary(...);
            usable = true;
        } catch (Throwable e) {
            Logger.log("Failed to load CryptoPP library", e);
        }
        */
        IS_USABLE = usable;
    }

    public CryptoppFactory() {
        if (!IS_USABLE) {
            throw new IllegalStateException("Library not loaded!");
        }
    }

    @Override
    public Signer getSigner(PrivateKey key) {
        return new CryptoppSigner(key);
    }

    @Override
    public Verifier getVerifier(PublicKey key) {
        return new CryptoppVerifier(key);
    }

    @Override
    public Encrypter getEncrypter(PrivateKey priv, PublicKey pub) {
        return new CryptoppEncrypter(priv, pub);
    }

    @Override
    public Decrypter getDecrypter(PrivateKey priv, PublicKey pub) {
        return new CryptoppDecrypter(priv, pub);
    }

    @Override
    public Generator getGenerator(Curve curve) {
        return new CryptoppGenerator(curve);
    }
}
