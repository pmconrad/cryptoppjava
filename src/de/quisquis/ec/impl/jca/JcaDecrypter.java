/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.jca;

import de.quisquis.ec.Decrypter;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/** Implements a @link{Decrypter} based on JCA.
 *
 * @author Peter Conrad
 */
public class JcaDecrypter implements Decrypter {
    private final PrivateKey key;
    private final Cipher cipher;

    public JcaDecrypter(PrivateKey key) {
        this.key = key;
        try {
            cipher = Cipher.getInstance("ECIES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("No ECIES?!", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        synchronized (cipher) {
            try {
                cipher.init(Cipher.DECRYPT_MODE, key);
                return cipher.doFinal(ciphertext);
            } catch (IllegalBlockSizeException | InvalidKeyException
                     | BadPaddingException e) {
                throw new IllegalStateException("Dencryption failed?!", e);
            }
        }
    }
}
