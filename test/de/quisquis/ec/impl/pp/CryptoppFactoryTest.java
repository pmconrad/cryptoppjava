/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.pp;

import de.quisquis.ec.AbstractFactoryTest;

import org.junit.BeforeClass;

/**
 *
 * @author Peter Conrad
 */
public class CryptoppFactoryTest extends AbstractFactoryTest {
    @BeforeClass
    public static void setUpClass() {
        instance = new CryptoppFactory();
        AbstractFactoryTest.setUpClass();
    }
}
