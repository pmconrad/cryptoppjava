/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec;

import java.security.KeyPair;

/** Provides a method for generating keypairs.
 *
 * @author Peter Conrad
 */
public interface Generator {
    /** @return a newly generated key pair using parameters already known to
     *          this Generator
     */
    public KeyPair generate();
}
