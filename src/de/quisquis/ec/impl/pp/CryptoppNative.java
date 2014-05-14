/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.pp;

import java.security.SignatureException;

/**
 *
 * @author Peter Conrad
 */
final class CryptoppNative {
    static native EcData generate(String curveName);

    static native byte[] sign(byte message[], byte modulus[], byte a[],
                              byte b[], byte gX[], byte gY[], byte n[],
                              byte x[])
            throws SignatureException;

    static native boolean verify(byte message[], byte signature[],
                                 byte modulus[], byte a[], byte b[],
                                 byte gX[], byte gY[], byte n[],
                                 byte qX[], byte qY[])
            throws SignatureException;

    static native byte[] encrypt(byte plaintext[],
                                 byte modulus[], byte a[], byte b[],
                                 byte gX[], byte gY[], byte n[],
                                 byte qX[], byte qY[]);

    static native byte[] decrypt(byte ciphertext[], byte modulus[], byte a[],
                                 byte b[], byte gX[], byte gY[], byte n[],
                                 byte x[]);
}
