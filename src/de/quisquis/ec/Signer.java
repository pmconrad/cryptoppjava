/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec;

import java.security.SignatureException;

/** Provides a method for creating a signature for a message.
 *
 * @author Peter Conrad
 */
public interface Signer {
    /** Signs the given message using a key already known to this Signer.
     * @param message the message to sign
     * @return a signature for the message
     * @throws SignatureException if something goes wrong
     */
    public byte[] sign(byte message[]) throws SignatureException;
}
