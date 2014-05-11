/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.jca;

import de.quisquis.ec.Encrypter;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/** Implements an @link{Encrypter} based on JCA.
 *
 * @author Peter Conrad
 */
public class JcaEncrypter implements Encrypter {
    private final PublicKey key;
    private final Cipher cipher;

    public JcaEncrypter(PublicKey key) {
        this.key = key;
        try {
            cipher = Cipher.getInstance("ECIES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("No ECIES?!", e);
        }
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        synchronized (cipher) {
            try {
                cipher.init(Cipher.ENCRYPT_MODE, key);
                return cipher.doFinal(plaintext);
            } catch (IllegalBlockSizeException | InvalidKeyException
                     | BadPaddingException e) {
                throw new IllegalStateException("Encryption failed?!", e);
            }
        }
    }
}
