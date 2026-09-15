/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.oidc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.apache.http.impl.client.HttpClients;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Characterization tests for {@link JWKPublicKeyLocator}.
 */
public class JWKPublicKeyLocatorTest {

    private static KeyPair rsaKeyPair1;
    private static KeyPair rsaKeyPair2;
    private static KeyPair ecKeyPair;

    private MockWebServer server;
    private JWKPublicKeyLocator locator;

    @BeforeClass
    public static void generateKeys() throws Exception {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        rsaKeyPair1 = rsaGen.generateKeyPair();
        rsaKeyPair2 = rsaGen.generateKeyPair();

        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(new ECGenParameterSpec("secp256r1"));
        ecKeyPair = ecGen.generateKeyPair();
    }

    @Before
    public void setUp() throws Exception {
        server = new MockWebServer();
        server.start();
        locator = new JWKPublicKeyLocator();
    }

    @After
    public void tearDown() throws Exception {
        server.shutdown();
    }

    // ------------------------------------------------------------------ //
    //  Caching and TTL                                                    //
    // ------------------------------------------------------------------ //

    @Test
    public void testCacheHitWithinTtl() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-1", rsaKeyPair1, "sig")));

        OidcClientConfiguration config = createConfig(300, 0);
        PublicKey first = locator.getPublicKey("kid-1", config);
        PublicKey second = locator.getPublicKey("kid-1", config);

        assertNotNull(first);
        assertSame(first, second);
        assertEquals(1, server.getRequestCount());
    }

    @Test
    public void testTtlExpiryForcesRefetch() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-1", rsaKeyPair1, "sig")));
        server.enqueue(jwksResponse(rsaJwkJson("kid-1", rsaKeyPair2, "sig")));

        OidcClientConfiguration config = createConfig(1, 0);
        PublicKey first = locator.getPublicKey("kid-1", config);
        assertNotNull(first);

        Thread.sleep(1500);

        PublicKey second = locator.getPublicKey("kid-1", config);
        assertNotNull(second);
        assertEquals(2, server.getRequestCount());
    }

    @Test
    public void testUnknownKidTriggersRefetch() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-1", rsaKeyPair1, "sig")));
        server.enqueue(jwksResponse(
                rsaJwkJson("kid-1", rsaKeyPair1, "sig"), rsaJwkJson("kid-2", rsaKeyPair2, "sig")));

        OidcClientConfiguration config = createConfig(300, 0);
        PublicKey first = locator.getPublicKey("kid-1", config);
        assertNotNull(first);
        assertEquals(1, server.getRequestCount());

        // getCurrentTime() returns seconds — must cross a second boundary
        // for the rate limiter's strict ">" check to pass
        Thread.sleep(1500);

        PublicKey second = locator.getPublicKey("kid-2", config);
        assertNotNull(second);
        assertEquals(2, server.getRequestCount());
    }

    // ------------------------------------------------------------------ //
    //  Rate limiting                                                      //
    // ------------------------------------------------------------------ //

    @Test
    public void testRefetchSuppressedWithinMinTime() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-1", rsaKeyPair1, "sig")));

        OidcClientConfiguration config = createConfig(300, 300);
        PublicKey first = locator.getPublicKey("kid-1", config);
        assertNotNull(first);

        PublicKey second = locator.getPublicKey("kid-unknown", config);
        assertNull(second);
        assertEquals(1, server.getRequestCount());
    }

    @Test
    public void testRateLimitedReturnsCachedKeyIfAvailable() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-1", rsaKeyPair1, "sig")));

        OidcClientConfiguration config = createConfig(300, 300);
        PublicKey first = locator.getPublicKey("kid-1", config);
        assertNotNull(first);

        PublicKey second = locator.getPublicKey("kid-1", config);
        assertNotNull(second);
        assertSame(first, second);
        assertEquals(1, server.getRequestCount());
    }

    // ------------------------------------------------------------------ //
    //  Failure handling                                                   //
    // ------------------------------------------------------------------ //

    @Test
    public void testEndpointFailurePreservesCache() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-1", rsaKeyPair1, "sig")));
        server.enqueue(new MockResponse().setResponseCode(500));

        OidcClientConfiguration config = createConfig(1, 0);
        PublicKey cached = locator.getPublicKey("kid-1", config);
        assertNotNull(cached);

        Thread.sleep(1500);

        PublicKey afterFailure = locator.getPublicKey("kid-1", config);
        assertNotNull(afterFailure);
        assertSame(cached, afterFailure);
    }

    @Test
    public void testEndpointFailureOnFirstFetch() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(500));

        OidcClientConfiguration config = createConfig(300, 0);
        PublicKey result = locator.getPublicKey("kid-1", config);
        assertNull(result);
    }

    // ------------------------------------------------------------------ //
    //  Reset                                                              //
    // ------------------------------------------------------------------ //

    @Test
    public void testResetForcesRefetch() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-1", rsaKeyPair1, "sig")));
        server.enqueue(jwksResponse(rsaJwkJson("kid-1", rsaKeyPair2, "sig")));

        OidcClientConfiguration config = createConfig(300, 300);
        PublicKey before = locator.getPublicKey("kid-1", config);
        assertNotNull(before);

        // reset() calls sendRequest directly, bypassing rate limiting
        locator.reset(config);
        assertEquals(2, server.getRequestCount());

        // after reset, cache is repopulated with new keys — cache hit
        PublicKey after = locator.getPublicKey("kid-1", config);
        assertNotNull(after);
    }

    // ------------------------------------------------------------------ //
    //  Null / empty edge cases                                            //
    // ------------------------------------------------------------------ //

    @Test
    public void testEmptyJwksResponse() throws Exception {
        server.enqueue(jwksResponse());

        OidcClientConfiguration config = createConfig(300, 0);
        PublicKey result = locator.getPublicKey("kid-1", config);
        assertNull(result);
    }

    /**
     * CURRENT BUG: when the JWKS response contains a key
     * without a "kid" field, JWKParser.getKeyId() returns null. The resulting
     * HashMap has a null key. ConcurrentHashMap.putAll() throws
     * NullPointerException because ConcurrentHashMap rejects null keys. Since
     * the catch block in sendRequest() only handles OidcException, the NPE
     * propagates to the caller. Additionally, currentKeys.clear() has already
     * executed before the NPE, so the cache is left empty.
     *
     * This test captures the current behavior, NOT the intended behavior.
     * A correct implementation should either skip keys without kid or handle
     * this case gracefully.
     */
    @Test(expected = NullPointerException.class)
    public void testJwksKeyWithoutKid() throws Exception {
        String keyJson = rsaJwkJsonNoKid(rsaKeyPair1, "sig");
        server.enqueue(jwksResponse(keyJson));

        OidcClientConfiguration config = createConfig(300, 0);
        locator.getPublicKey("any-kid", config);
    }

    // ------------------------------------------------------------------ //
    //  Key filtering (FOR_SIGNATURE_VALIDATION)                           //
    // ------------------------------------------------------------------ //

    @Test
    public void testEncryptionKeysExcluded() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-enc", rsaKeyPair1, "enc")));

        OidcClientConfiguration config = createConfig(300, 0);
        PublicKey result = locator.getPublicKey("kid-enc", config);
        assertNull(result);
    }

    @Test
    public void testKeyOpsVerifyIncluded() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJsonWithKeyOps("kid-verify", rsaKeyPair1, "verify")));

        OidcClientConfiguration config = createConfig(300, 0);
        PublicKey result = locator.getPublicKey("kid-verify", config);
        assertNotNull(result);
    }

    @Test
    public void testEcKeyParsedCorrectly() throws Exception {
        server.enqueue(jwksResponse(ecJwkJson("kid-ec", ecKeyPair, "sig")));

        OidcClientConfiguration config = createConfig(300, 0);
        PublicKey result = locator.getPublicKey("kid-ec", config);
        assertNotNull(result);
        assertTrue(result instanceof ECPublicKey);
    }

    // ------------------------------------------------------------------ //
    //  Test infrastructure                                                //
    // ------------------------------------------------------------------ //

    private OidcClientConfiguration createConfig(int cacheTtlSeconds, int minTimeBetweenRequestsSeconds) {
        OidcClientConfiguration config = new OidcClientConfiguration();
        config.jwksUrl = server.url("/jwks").toString();
        config.authUrl = "http://dummy";
        config.resource = "test-client";
        config.publicKeyCacheTtl = cacheTtlSeconds;
        config.minTimeBetweenJwksRequests = minTimeBetweenRequestsSeconds;
        config.setClient(HttpClients.createDefault());
        return config;
    }

    private static MockResponse jwksResponse(String... keyJsonEntries) {
        String keys = String.join(",", keyJsonEntries);
        String body = "{\"keys\":[" + keys + "]}";
        return new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }

    private static String rsaJwkJson(String kid, KeyPair keyPair, String use) {
        RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
        return "{" +
                "\"kty\":\"RSA\"," +
                "\"kid\":\"" + kid + "\"," +
                "\"use\":\"" + use + "\"," +
                "\"n\":\"" + base64urlUInt(pub.getModulus()) + "\"," +
                "\"e\":\"" + base64urlUInt(pub.getPublicExponent()) + "\"" +
                "}";
    }

    private static String rsaJwkJsonNoKid(KeyPair keyPair, String use) {
        RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
        return "{" +
                "\"kty\":\"RSA\"," +
                "\"use\":\"" + use + "\"," +
                "\"n\":\"" + base64urlUInt(pub.getModulus()) + "\"," +
                "\"e\":\"" + base64urlUInt(pub.getPublicExponent()) + "\"" +
                "}";
    }

    private static String rsaJwkJsonWithKeyOps(String kid, KeyPair keyPair, String keyOp) {
        RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
        return "{" +
                "\"kty\":\"RSA\"," +
                "\"kid\":\"" + kid + "\"," +
                "\"key_ops\":[\"" + keyOp + "\"]," +
                "\"n\":\"" + base64urlUInt(pub.getModulus()) + "\"," +
                "\"e\":\"" + base64urlUInt(pub.getPublicExponent()) + "\"" +
                "}";
    }

    private static String ecJwkJson(String kid, KeyPair keyPair, String use) {
        ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
        return "{" +
                "\"kty\":\"EC\"," +
                "\"kid\":\"" + kid + "\"," +
                "\"use\":\"" + use + "\"," +
                "\"crv\":\"P-256\"," +
                "\"x\":\"" + base64urlUInt(pub.getW().getAffineX()) + "\"," +
                "\"y\":\"" + base64urlUInt(pub.getW().getAffineY()) + "\"" +
                "}";
    }

    private static String base64urlUInt(BigInteger value) {
        byte[] bytes = value.toByteArray();
        int start = 0;
        while (start < bytes.length && bytes[start] == 0) {
            start++;
        }
        if (start > 0 && start < bytes.length) {
            bytes = Arrays.copyOfRange(bytes, start, bytes.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
