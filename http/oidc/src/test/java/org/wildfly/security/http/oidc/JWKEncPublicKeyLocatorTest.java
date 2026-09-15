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
import static org.junit.Assert.assertSame;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
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
 * Characterization tests for {@link JWKEncPublicKeyLocator}.
 */
public class JWKEncPublicKeyLocatorTest {

    private static KeyPair rsaKeyPair1;
    private static KeyPair rsaKeyPair2;

    private MockWebServer server;
    private JWKEncPublicKeyLocator locator;

    @BeforeClass
    public static void generateKeys() throws Exception {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        rsaKeyPair1 = rsaGen.generateKeyPair();
        rsaKeyPair2 = rsaGen.generateKeyPair();
    }

    @Before
    public void setUp() throws Exception {
        server = new MockWebServer();
        server.start();
        locator = new JWKEncPublicKeyLocator();
    }

    @After
    public void tearDown() throws Exception {
        server.shutdown();
    }

    // ------------------------------------------------------------------ //
    //  Basic behavior                                                     //
    // ------------------------------------------------------------------ //

    @Test
    public void testKidIsIgnored() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-enc-1", rsaKeyPair1, "enc")));

        OidcClientConfiguration config = createConfig(300, 0);
        PublicKey withKid = locator.getPublicKey("kid-enc-1", config);
        PublicKey withDifferentKid = locator.getPublicKey("totally-wrong-kid", config);
        PublicKey withNull = locator.getPublicKey(null, config);

        assertNotNull(withKid);
        assertSame(withKid, withDifferentKid);
        assertSame(withKid, withNull);
    }

    @Test
    public void testForEncryptionFiltering() throws Exception {
        server.enqueue(jwksResponse(
                rsaJwkJson("kid-sig", rsaKeyPair1, "sig"),
                rsaJwkJson("kid-enc", rsaKeyPair2, "enc")));

        OidcClientConfiguration config = createConfig(300, 0);
        PublicKey result = locator.getPublicKey("kid-enc", config);
        assertNotNull(result);
        assertEquals(rsaKeyPair2.getPublic(), result);
    }

    /**
     * CURRENT BUG: when the JWKS response contains NO
     * encryption keys, the internal list is empty after sendRequest(). The
     * lookupCachedKey() method unconditionally calls currentKeys.get(0) without
     * checking if the list is empty, causing an IndexOutOfBoundsException.
     */
    @Test(expected = IndexOutOfBoundsException.class)
    public void testEmptyEncryptionKeysThrowsIndexOutOfBounds() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-sig", rsaKeyPair1, "sig")));

        OidcClientConfiguration config = createConfig(300, 0);
        locator.getPublicKey("any", config);
    }

    // ------------------------------------------------------------------ //
    //  Caching                                                            //
    // ------------------------------------------------------------------ //

    @Test
    public void testCacheHitWithinTtl() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-enc", rsaKeyPair1, "enc")));

        OidcClientConfiguration config = createConfig(300, 0);
        PublicKey first = locator.getPublicKey("kid-enc", config);
        PublicKey second = locator.getPublicKey("kid-enc", config);

        assertNotNull(first);
        assertSame(first, second);
        assertEquals(1, server.getRequestCount());
    }

    // ------------------------------------------------------------------ //
    //  Rate limiting                                                      //
    // ------------------------------------------------------------------ //

    @Test
    public void testRateLimiting() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-enc", rsaKeyPair1, "enc")));

        OidcClientConfiguration config = createConfig(1, 300);
        locator.getPublicKey("kid-enc", config);

        Thread.sleep(1500);

        locator.getPublicKey("kid-enc", config);
        assertEquals(1, server.getRequestCount());
    }

    // ------------------------------------------------------------------ //
    //  Reset                                                              //
    // ------------------------------------------------------------------ //

    @Test
    public void testResetForcesRefetch() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-enc", rsaKeyPair1, "enc")));
        server.enqueue(jwksResponse(rsaJwkJson("kid-enc", rsaKeyPair2, "enc")));

        OidcClientConfiguration config = createConfig(300, 300);
        PublicKey before = locator.getPublicKey("kid-enc", config);
        assertNotNull(before);

        // reset() calls sendRequest directly, bypassing rate limiting
        locator.reset(config);
        assertEquals(2, server.getRequestCount());

        // after reset, cache is repopulated — getPublicKey is a cache hit
        PublicKey after = locator.getPublicKey("kid-enc", config);
        assertNotNull(after);
    }

    // ------------------------------------------------------------------ //
    //  Failure handling                                                   //
    // ------------------------------------------------------------------ //

    @Test
    public void testFailurePreservesCache() throws Exception {
        server.enqueue(jwksResponse(rsaJwkJson("kid-enc", rsaKeyPair1, "enc")));
        server.enqueue(new MockResponse().setResponseCode(500));

        OidcClientConfiguration config = createConfig(1, 0);
        PublicKey cached = locator.getPublicKey("kid-enc", config);
        assertNotNull(cached);

        Thread.sleep(1500);

        PublicKey afterFailure = locator.getPublicKey("kid-enc", config);
        assertNotNull(afterFailure);
        assertSame(cached, afterFailure);
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
