/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.pp;

import de.quisquis.ec.Verifier;

import java.security.PublicKey;
import java.security.SignatureException;

import java.security.interfaces.ECPublicKey;

/**
 *
 * @author Peter Conrad
 */
public class CryptoppVerifier implements Verifier {
    private final EcData keyData;

    public CryptoppVerifier(PublicKey key) {
        keyData = new EcData((ECPublicKey) key);
    }

    @Override
    public boolean verify(byte[] message, byte[] signature)
            throws SignatureException {
        return CryptoppNative.verify(message, signature, keyData.curveModulus,
                                     keyData.curveA, keyData.curveB,
                                     keyData.gX, keyData.gY, keyData.n,
                                     keyData.qX, keyData.qY);
    }
}
