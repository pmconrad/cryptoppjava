/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec;

/** Standardized elliptic curves by name.
 *
 * @author Peter Conrad
 */
public enum Curve {
    P192K1("secp192k1"), P192R1("secp192r1"),
    P224K1("secp224k1"), P224R1("secp224r1"),
    P256K1("secp256k1"), P256R1("secp256r1"),
    P384R1("secp384r1");

    private final String identifier;

    private Curve(String id) {
        this.identifier = id;
    }

    /** @return the JCA parameter identifier for this curve */
    public String getIdentifier() { return identifier; }
}
