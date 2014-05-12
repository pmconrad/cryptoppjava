/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.bc;

import de.quisquis.ec.Signer;

import java.security.InvalidKeyException;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

/** Implements a @link{Signer} based on JCA.
 *
 * @author Peter Conrad
 */
public class BouncySigner implements Signer {
    private final PrivateKey key;
    private final Signature signature;

    public BouncySigner(PrivateKey key) {
        this.key = key;
        try {
            signature = Signature.getInstance("ECDSA", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
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
