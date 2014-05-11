/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.jca;

import de.quisquis.ec.Verifier;

import java.security.InvalidKeyException;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/** Implements a @link{Verifier} based on JCA.
 *
 * @author Peter Conrad
 */
public class JcaVerifier implements Verifier {
    private final PublicKey key;
    private final Signature signator;

    public JcaVerifier(PublicKey key) {
        this.key = key;
        try {
            signator = Signature.getInstance("ECDSA");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No ECDSA?!", e);
        }
    }

    @Override
    public boolean verify(byte[] message, byte[] signature) throws SignatureException {
        synchronized (signator) {
            try {
                signator.initVerify(key);
            } catch (InvalidKeyException e) {
                throw new SignatureException("Invalid key?!", e);
            }
            signator.update(message);
            return signator.verify(signature);
        }
    }
}
