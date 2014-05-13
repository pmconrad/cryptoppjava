/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.pp;

import de.quisquis.ec.Decrypter;

import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.interfaces.ECPrivateKey;

/**
 *
 * @author Peter Conrad
 */
public class CryptoppDecrypter implements Decrypter {
    private final EcData keyData;

    public CryptoppDecrypter(PrivateKey priv, PublicKey pub) {
        keyData = new EcData((ECPrivateKey) priv);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        return CryptoppNative.decrypt(ciphertext, keyData.curveModulus,
                                      keyData.curveA, keyData.curveB,
                                      keyData.gX, keyData.gY, keyData.n,
                                      keyData.x);
    }
}
