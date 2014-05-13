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
        byte generated[][] = CryptoppNative.generate(curve.getIdentifier());
        BigInteger p = new BigInteger(generated[0]);
        BigInteger a = new BigInteger(generated[1]);
        BigInteger b = new BigInteger(generated[2]);
        ECCurve ec = new ECCurve.Fp(p, a, b);
        BigInteger gX = new BigInteger(generated[3]);
        BigInteger gY = new BigInteger(generated[4]);
        ECPoint g = ec.createPoint(gX, gY);
        BigInteger n = new BigInteger(generated[5]);
        ECDomainParameters params = new ECDomainParameters(ec, g, n);
        BigInteger x = new BigInteger(generated[6]);
        ECPrivateKeyParameters privParams;
        privParams = new ECPrivateKeyParameters(x, params);
        ECPrivateKey privKey = new JCEECPrivateKey("EC", privParams);
        return new KeyPair(derivePubkey(privKey, params), privKey);
    }

    private static ECPublicKey derivePubkey(ECPrivateKey privKey,
                                            ECDomainParameters params) {
        ECPoint q = params.getG().multiply(privKey.getS());
        ECPublicKeyParameters pubParams = new ECPublicKeyParameters(q, params);
        return new JCEECPublicKey(privKey.getAlgorithm(), pubParams);
    }
}
