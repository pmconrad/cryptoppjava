/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.pp;

import de.quisquis.ec.Signer;

import java.security.PrivateKey;
import java.security.SignatureException;

import java.security.interfaces.ECPrivateKey;

/**
 *
 * @author Peter Conrad
 */
public class CryptoppSigner implements Signer {
    private final EcData keyData;

    public CryptoppSigner(PrivateKey key) {
        keyData = new EcData((ECPrivateKey) key);
    }

    @Override
    public byte[] sign(byte[] message) throws SignatureException {
        return CryptoppNative.sign(message, keyData.curveModulus,
                                   keyData.curveA, keyData.curveB,
                                   keyData.gX, keyData.gY, keyData.n,
                                   keyData.x);
    }
}
