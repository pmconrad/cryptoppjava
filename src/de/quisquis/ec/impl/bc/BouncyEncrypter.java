/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.bc;

import de.quisquis.ec.Encrypter;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.interfaces.IESKey;

import org.bouncycastle.jce.spec.IEKeySpec;

/** Implements an @link{Encrypter} based on JCA.
 *
 * @author Peter Conrad
 */
public class BouncyEncrypter implements Encrypter {
    private final IESKey key;
    private final Cipher cipher;

    public BouncyEncrypter(PrivateKey priv, PublicKey pub) {
        key = new IEKeySpec(priv, pub);
        try {
            cipher = Cipher.getInstance("ECIES", "BC");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                 | NoSuchProviderException  e) {
            throw new IllegalStateException("No ECIES?!", e);
        }
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        synchronized (cipher) {
            try {
                cipher.init(Cipher.ENCRYPT_MODE, key, new SecureRandom());
                return cipher.doFinal(plaintext);
            } catch (IllegalBlockSizeException | InvalidKeyException
                     | BadPaddingException e) {
                throw new IllegalStateException("Encryption failed?!", e);
            }
        }
    }
}
