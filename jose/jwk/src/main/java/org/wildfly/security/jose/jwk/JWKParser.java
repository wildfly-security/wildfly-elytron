/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.jose.jwk;

import static org.wildfly.security.jose.jwk.ElytronMessages.log;
import static org.wildfly.security.jose.jwk.JWKUtil.BASE64_URL;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.json.util.JsonSerialization;

/**
 * A JWK parser.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.14.0
 */
public class JWKParser {

    private JWK jwk;

    private JWKParser() {
    }

    public JWKParser(JWK jwk) {
        this.jwk = jwk;
    }

    public static JWKParser create() {
        return new JWKParser();
    }

    public static JWKParser create(JWK jwk) {
        return new JWKParser(jwk);
    }

    public JWKParser parse(String jwk) {
        try {
            this.jwk = JsonSerialization.mapper.readValue(jwk, JWK.class);
            return this;
        } catch (Exception e) {
            throw log.unableToParseStringJWK(e);
        }
    }

    public JWK getJwk() {
        return jwk;
    }

    public PublicKey toPublicKey() {
        String keyType = jwk.getKeyType();
        if (keyType.equals(RSAPublicJWK.RSA)) {
            return createRSAPublicKey();
        } else if (keyType.equals(ECPublicJWK.EC)) {
            return createECPublicKey();
        } else {
            throw log.unsupportedKeyTypeForJWK(keyType);
        }
    }

    public boolean isKeyTypeSupported(String keyType) {
        return (RSAPublicJWK.RSA.equals(keyType) || ECPublicJWK.EC.equals(keyType));
    }

    private PublicKey createECPublicKey() {
        String crv = (String) jwk.getOtherClaims().get(ECPublicJWK.CRV);

        BigInteger x = new BigInteger(1,
                CodePointIterator.ofString((String) jwk.getOtherClaims().get(ECPublicJWK.X)).base64Decode(BASE64_URL, false).drain());
        BigInteger y = new BigInteger(1,
                CodePointIterator.ofString((String) jwk.getOtherClaims().get(ECPublicJWK.Y)).base64Decode(BASE64_URL, false).drain());

        String curveName;
        switch (crv) {
            case "P-256" :
                curveName = "secp256r1";
                break;
            case "P-384" :
                curveName = "secp384r1";
                break;
            case "P-521" :
                curveName = "secp521r1";
                break;
            default :
                throw log.unsupportedCurve();
        }

        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curveName));
            ECPoint point = new ECPoint(x, y);

            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePublic(new ECPublicKeySpec(point, params.getParameterSpec(ECParameterSpec.class)));
        } catch (Exception e) {
            throw log.unableToCreatePublicKeyFromJWK(e);
        }
    }

    private PublicKey createRSAPublicKey() {
        BigInteger modulus = new BigInteger(1,
                CodePointIterator.ofString(jwk.getOtherClaims().get(RSAPublicJWK.MODULUS).toString()).base64Decode(BASE64_URL, false).drain());
        BigInteger publicExponent = new BigInteger(1,
                CodePointIterator.ofString(jwk.getOtherClaims().get(RSAPublicJWK.PUBLIC_EXPONENT).toString()).base64Decode(BASE64_URL, false).drain());

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        } catch (Exception e) {
            throw log.unableToCreatePublicKeyFromJWK(e);
        }
    }

}
