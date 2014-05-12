/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.bc;

import de.quisquis.ec.Decrypter;

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

/** Implements a @link{Decrypter} based on JCA.
 *
 * @author Peter Conrad
 */
public class BouncyDecrypter implements Decrypter {
    private final IESKey key;
    private final Cipher cipher;

    public BouncyDecrypter(PrivateKey priv, PublicKey pub) {
        key = new IEKeySpec(priv, pub);
        try {
            cipher = Cipher.getInstance("ECIES", "BC");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                 | NoSuchProviderException  e) {
            throw new IllegalStateException("No ECIES?!", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        synchronized (cipher) {
            try {
                cipher.init(Cipher.DECRYPT_MODE, key, new SecureRandom());
                return cipher.doFinal(ciphertext);
            } catch (IllegalBlockSizeException | InvalidKeyException
                     | BadPaddingException e) {
                throw new IllegalStateException("Dencryption failed?!", e);
            }
        }
    }
}
