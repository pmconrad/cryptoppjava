/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec;

import java.security.SignatureException;

/** Provides a method for verifying a signature for a message.
 *
 * @author Peter Conrad
 */
public interface Verifier {
    /** Verifies that the given message matches the given signature, using a
     *  verification key known to this Verifier.
     * @param message the message to verify
     * @param signature the signature to verify
     * @return true iff the signature is valid wrt the known key and matches the
     *              message
     * @throws SignatureException if something goes wrong
     */
    public boolean verify(byte message[], byte signature[]) throws SignatureException;
}
