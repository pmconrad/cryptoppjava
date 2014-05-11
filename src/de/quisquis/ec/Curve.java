/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec;

/** Standardized elliptic curves by name.
 *
 * @author Peter Conrad
 */
public enum Curve {
    P192V1("prime192v1");

    private final String identifier;

    private Curve(String id) {
        this.identifier = id;
    }

    /** @return the JCA parameter identifier for this curve */
    public String getIdentifier() { return identifier; }
}
