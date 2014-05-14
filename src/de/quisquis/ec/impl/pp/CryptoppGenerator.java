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

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

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
     *  elliptic curve math and its ECKey implementations. The JDK doesn't have
     *  these implementations, and it doesn't make sense to re-implement them
     *  myself.
     * @return a newly generated key pair on this Generator's curve */
    @Override
    public KeyPair generate() {
        EcData generated = CryptoppNative.generate(curve.getIdentifier());
        BigInteger p = new BigInteger(generated.curveModulus);
        BigInteger a = new BigInteger(generated.curveA);
        BigInteger b = new BigInteger(generated.curveB);
        ECCurve ec = new ECCurve.Fp(p, a, b);
        BigInteger gX = new BigInteger(generated.gX);
        BigInteger gY = new BigInteger(generated.gY);
        ECPoint g = ec.createPoint(gX, gY);
        BigInteger n = new BigInteger(generated.n);
        ECDomainParameters params = new ECDomainParameters(ec, g, n);
        BigInteger qX = new BigInteger(generated.qX);
        BigInteger qY = new BigInteger(generated.qY);
        ECPoint q = ec.createPoint(qX, qY);
        ECPublicKeyParameters pubParams = new ECPublicKeyParameters(q, params);
        ECPublicKey pubKey = new JCEECPublicKey("EC", pubParams);
        BigInteger x = new BigInteger(generated.x);
        ECPrivateKeyParameters privParams;
        privParams = new ECPrivateKeyParameters(x, params);
        ECPrivateKey privKey = new JCEECPrivateKey(pubKey.getAlgorithm(),
                                                   privParams);
        return new KeyPair(pubKey, privKey);
    }
}
