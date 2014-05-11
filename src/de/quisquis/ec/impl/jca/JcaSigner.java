/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.jca;

import de.quisquis.ec.Signer;

import java.security.InvalidKeyException;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

/** Implements a @link{Signer} based on JCA.
 *
 * @author Peter Conrad
 */
public class JcaSigner implements Signer {
    private final PrivateKey key;
    private final Signature signature;

    public JcaSigner(PrivateKey key) {
        this.key = key;
        try {
            signature = Signature.getInstance("ECDSA");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No ECDSA?!", e);
        }
    }

    @Override
    public byte[] sign(byte[] message) throws SignatureException {
        synchronized (signature) {
            try {
                signature.initSign(key);
            } catch (InvalidKeyException e) {
                throw new SignatureException("Invalid key?!", e);
            }
            signature.update(message);
            return signature.sign();
        }
    }
}
