/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.pp;

import de.quisquis.ec.Curve;
import de.quisquis.ec.Generator;

import java.math.BigInteger;

import java.security.KeyPair;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;

/** A CryptoPP-based @link{Generator} implementation.
 *
 * @author Peter Conrad
 */
public class CryptoppGenerator implements Generator {
    private final Curve curve;

    /** Constructor defining the curve on which keys are to be used.
     * @param curve the standardized curve on which to generate keys
     */
    public CryptoppGenerator(Curve curve) {
        this.curve = curve;
    }

    /** Note: there is some cheating involved here in that I use bouncycastle's
     *  ECKey implementations. The JDK doesn't have
     *  these implementations, and it doesn't make sense to re-implement them
     *  myself.
     * @return a newly generated key pair on this Generator's curve */
    @Override
    public KeyPair generate() {
        EcData generated = CryptoppNative.generate(curve.getIdentifier());
        BigInteger p = new BigInteger(generated.curveModulus);
        ECField field = new ECFieldFp(p);

        BigInteger a = new BigInteger(generated.curveA);
        BigInteger b = new BigInteger(generated.curveB);
        EllipticCurve ec = new EllipticCurve(field, a, b);

        BigInteger gX = new BigInteger(generated.gX);
        BigInteger gY = new BigInteger(generated.gY);
        ECPoint g = new ECPoint(gX, gY);
        BigInteger n = new BigInteger(generated.n);
        ECParameterSpec params = new ECParameterSpec(ec, g, n, 1);

        BigInteger qX = new BigInteger(generated.qX);
        BigInteger qY = new BigInteger(generated.qY);
        ECPoint q = new ECPoint(qX, qY);
        ECPublicKeySpec pubParams = new ECPublicKeySpec(q, params);
        ECPublicKey pubKey = new JCEECPublicKey("EC", pubParams);

        BigInteger x = new BigInteger(generated.x);
        ECPrivateKeySpec privParams;
        privParams = new ECPrivateKeySpec(x, params);
        ECPrivateKey privKey = new JCEECPrivateKey(pubKey.getAlgorithm(),
                                                   privParams);
        return new KeyPair(pubKey, privKey);
    }
}
