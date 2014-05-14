/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.pp;

import de.quisquis.ec.AbstractSpeedTest;

import org.junit.BeforeClass;

/**
 *
 * @author Peter Conrad
 */
public class CryptoppSpeedTest extends AbstractSpeedTest {
    @BeforeClass
    public static void setUpClass() {
        instance = new CryptoppFactory();
        AbstractSpeedTest.setUpClass();
    }
}
