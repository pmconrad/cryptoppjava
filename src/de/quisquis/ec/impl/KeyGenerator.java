/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl;

import de.quisquis.ec.Curve;
import de.quisquis.ec.Generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.security.spec.ECGenParameterSpec;

/** A JCA-based @link{Generator} implementation.
 *
 * @author Peter Conrad
 */
public class KeyGenerator implements Generator {
    private final KeyPairGenerator generator;

    /** Constructor defining the curve on which keys are to be used.
     * @param curve the standardized curve on which to generate keys
     */
    public KeyGenerator(Curve curve) {
        try {
            generator = KeyPairGenerator.getInstance("ECDSA");
            generator.initialize(new ECGenParameterSpec(curve.getIdentifier()),
                                 new SecureRandom());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Unsupported curve " + curve + "?!");
        }
    }

    /** @return a newly generated key pair on this Generator's curve */
    @Override
    public KeyPair generate() {
        return generator.generateKeyPair();
    }
}
