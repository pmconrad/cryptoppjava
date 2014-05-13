/* (C) 2014 Peter Conrad
 * All rights reserved.
 */
package de.quisquis.ec.impl.pp;

import java.math.BigInteger;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 *
 * @author Peter Conrad
 */
class EcData {
    final byte[] curveModulus, curveA, curveB;
    final byte[] gX, gY, n;
    final byte[] qX, qY, x;

    private EcData(ECKey key, ECPoint q, BigInteger x) {
        ECParameterSpec params = key.getParams();
        EllipticCurve curve = params.getCurve();
        curveModulus = ((ECFieldFp) curve.getField()).getP().toByteArray();
        curveA = curve.getA().toByteArray();
        curveB = curve.getB().toByteArray();
        gX = params.getGenerator().getAffineX().toByteArray();
        gY = params.getGenerator().getAffineY().toByteArray();
        n = params.getOrder().toByteArray();
        if (q == null) {
            qX = null;
            qY = null;
        } else {
            qX = q.getAffineX().toByteArray();
            qY = q.getAffineY().toByteArray();
        }
        this.x = x == null ? null : x.toByteArray();
    }

    public EcData(ECPrivateKey key) {
        this(key, null, key.getS());
    }

    public EcData(ECPublicKey key) {
        this(key, key.getW(), null);
    }
}
