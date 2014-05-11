/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec;

/** Provide a method for encryption.
 *
 * @author Peter Conrad
 */
public interface Encrypter {
    /** Encrypts the given plaintext using a key already known to this
     *  Encrypter.
     * @param plaintext the message to encrypt
     * @return the ciphertext
     * @throws IllegalStateException if something goes wrong
     */
    public byte[] encrypt(byte plaintext[]);
}
