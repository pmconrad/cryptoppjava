/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.pp;

import de.quisquis.ec.Encrypter;

import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;

/**
 *
 * @author Peter Conrad
 */
public class CryptoppEncrypter implements Encrypter {
    private final EcData keyData;

    public CryptoppEncrypter(PrivateKey priv, PublicKey pub) {
        keyData = new EcData((ECPublicKey) pub);
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        return CryptoppNative.encrypt(plaintext, keyData.curveModulus,
                                      keyData.curveA, keyData.curveB,
                                      keyData.gX, keyData.gY, keyData.n,
                                      keyData.qX, keyData.qY);
    }
}
