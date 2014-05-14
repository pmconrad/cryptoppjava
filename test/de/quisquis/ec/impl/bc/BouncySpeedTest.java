/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.bc;

import de.quisquis.ec.AbstractSpeedTest;

import org.junit.BeforeClass;

/**
 *
 * @author Peter Conrad
 */
public class BouncySpeedTest extends AbstractSpeedTest {
    @BeforeClass
    public static void setUpClass() {
        instance = new BouncyFactory();
        AbstractSpeedTest.setUpClass();
    }
}
