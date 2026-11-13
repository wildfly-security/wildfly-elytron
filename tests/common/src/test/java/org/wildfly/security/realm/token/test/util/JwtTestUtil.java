/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.realm.token.test.util;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.util.Arrays;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonValue;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * A utility class containing common methods for working with token realms.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class JwtTestUtil extends JwkTestUtil {

    public static String createJwt(KeyPair keyPair, int expirationOffset, int notBeforeOffset) throws Exception {
        return createJwt(keyPair, expirationOffset, notBeforeOffset, null, null);
    }

    public static String createJwt(KeyPair keyPair, int expirationOffset) throws Exception {
        return createJwt(keyPair, expirationOffset, -1);
    }

    // Retain the original method signature for RSA (Bearer JWT token) generation
    public static String createJwt(KeyPair keyPair, int expirationOffset, int notBeforeOffset, String kid, URI jku) throws Exception {
        return createJwt(new RSASSASigner(keyPair.getPrivate()), JWSAlgorithm.RS256,
            expirationOffset, notBeforeOffset, kid, jku);
    }

    // Support for RSA and EC JWT token generation.
    public static String createJwt(JWSSigner signer, JWSAlgorithm algorithm, int expirationOffset, int notBeforeOffset, String kid, URI jku) throws Exception {

        JsonObjectBuilder claimsBuilder = createClaims(expirationOffset, notBeforeOffset);

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(algorithm)
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

    public static String createHS256Jwt(String secret, int expirationOffset, String issuer, String audience, String subject, String preferredUsername) throws Exception {
        JWSSigner signer = new MACSigner(secret);

        JsonObjectBuilder claimsBuilder = Json.createObjectBuilder()
                .add("sub", subject)
                .add("iss", issuer)
                .add("aud", audience)
                .add("exp", (System.currentTimeMillis() / 1000) + expirationOffset)
                .add("preferred_username", preferredUsername);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(new JOSEObjectType("JWT"))
                .build();

        JWSObject jwsObject = new JWSObject(header, new Payload(claimsBuilder.build().toString()));
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    public static String createHS256JwtForOAuth2() {
        String secret = "longenoughsecretthatisstleast256bitslong";

        try {
            return createHS256Jwt(secret, 600, "auth.server", "for_me", "1234567890", "jdoe");
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate JWT token", e);
        }
    }
}
