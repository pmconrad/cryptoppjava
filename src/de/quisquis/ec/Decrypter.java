/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec;

/** Provides a method for decryption.
 *
 * @author Peter Conrad
 */
public interface Decrypter {
    /** Decrypts the given ciphertext using a decryption key already known to
     *  this Decrypter.
     * @param ciphertext the ciphertext to decrypt
     * @return the plaintext
     * @throws IllegalStateException if something goes wrong (including MAC
     * mismatch after decryption)
     */
    public byte[] decrypt(byte ciphertext[]);
}
