/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.realm.token.test.util;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * A utility class containing common methods for working with token realms.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class JwtTestUtil {

    public static JsonObject jwksToJson(RsaJwk... jwks) {
        JsonArrayBuilder jab = Json.createArrayBuilder();
        for (int i = 0; i < jwks.length; i++){
            JsonObjectBuilder jwk = Json.createObjectBuilder()
                    .add("kty", jwks[i].getKty())
                    .add("alg", jwks[i].getAlg())
                    .add("kid", jwks[i].getKid())
                    .add("n", jwks[i].getN())
                    .add("e", jwks[i].getE());
            jab.add(jwk);
        }
        return Json.createObjectBuilder().add("keys", jab).build();
    }

    public static String createJwt(KeyPair keyPair, int expirationOffset, int notBeforeOffset) throws Exception {
        return createJwt(keyPair, expirationOffset, notBeforeOffset, null, null);
    }

    public static String createJwt(KeyPair keyPair, int expirationOffset) throws Exception {
        return createJwt(keyPair, expirationOffset, -1);
    }

    public static String createJwt(KeyPair keyPair, int expirationOffset, int notBeforeOffset, String kid, URI jku) throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        JWSSigner signer = new RSASSASigner(privateKey);
        JsonObjectBuilder claimsBuilder = createClaims(expirationOffset, notBeforeOffset);

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("jwt"));

        if (jku != null) {
            headerBuilder.jwkURL(jku);
        }
        if (kid != null) {
            headerBuilder.keyID(kid);
        }

        JWSObject jwsObject = new JWSObject(headerBuilder.build(), new Payload(claimsBuilder.build().toString()));

        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    public static String createJwt(KeyPair keyPair) throws Exception {
        return createJwt(keyPair, 60);
    }

    public static JsonObjectBuilder createClaims(int expirationOffset, int notBeforeOffset) {
        return createClaims(expirationOffset, notBeforeOffset, null);
    }
    public static JsonObjectBuilder createClaims(int expirationOffset, int notBeforeOffset, JsonObject additionalClaims) {
        JsonObjectBuilder claimsBuilder = Json.createObjectBuilder()
                .add("active", true)
                .add("sub", "elytron@jboss.org")
                .add("iss", "elytron-oauth2-realm")
                .add("aud", Json.createArrayBuilder().add("my-app-valid").add("third-app-valid").add("another-app-valid").build())
                .add("exp", (System.currentTimeMillis() / 1000) + expirationOffset);

        if (additionalClaims != null) {
            for(String name : additionalClaims.keySet()) {
                JsonValue value = additionalClaims.get(name);
                claimsBuilder.add(name, value);
            }
        }
        if (notBeforeOffset > 0) {
            claimsBuilder.add("nbf", (System.currentTimeMillis() / 1000) + notBeforeOffset);
        }

        return claimsBuilder;
    }

    public static RsaJwk createRsaJwk(KeyPair keyPair, String kid) {
        RSAPublicKey pk = (RSAPublicKey) keyPair.getPublic();
        RsaJwk jwk = new RsaJwk();

        jwk.setAlg("RS256");
        jwk.setKid(kid);
        jwk.setKty("RSA");
        jwk.setE(Base64.getUrlEncoder().withoutPadding().encodeToString(toBase64urlUInt(pk.getPublicExponent())));
        jwk.setN(Base64.getUrlEncoder().withoutPadding().encodeToString(toBase64urlUInt(pk.getModulus())));

        return jwk;
    }

    public static Dispatcher createTokenDispatcher(String response) {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest recordedRequest) {
                return new MockResponse().setBody(response);
            }
        };
    }

    // rfc7518 dictates the use of Base64urlUInt for "n" and "e" and it explicitly mentions that the
    // minimum number of octets should be used and the 0 leading sign byte should not be included
    private static byte[] toBase64urlUInt(final BigInteger bigInt) {
        byte[] bytes = bigInt.toByteArray();
        int i = 0;
        while (i < bytes.length && bytes[i] == 0) {
            i++;
        }
        if (i > 0 && i < bytes.length) {
            return Arrays.copyOfRange(bytes, i, bytes.length);
        } else {
            return bytes;
        }
    }

}
