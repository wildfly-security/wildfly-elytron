/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jose.jwks;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.jose.jwk.JsonWebKeySetUtil.FOR_SIGNATURE_VALIDATION;

import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for {@link JwksCache}.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
public class JwksCacheTest {

    private static KeyPair rsaKeyPair1;
    private static KeyPair rsaKeyPair2;
    private static KeyPair ecKeyPair;
    private static URL url1;
    private static URL url2;

    @BeforeClass
    public static void init() throws Exception {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        rsaKeyPair1 = rsaGen.generateKeyPair();
        rsaKeyPair2 = rsaGen.generateKeyPair();

        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(new ECGenParameterSpec("secp256r1"));
        ecKeyPair = ecGen.generateKeyPair();

        url1 = new URL("http://localhost/jwks1");
        url2 = new URL("http://localhost/jwks2");
    }

    // ------------------------------------------------------------------ //
    //  needsRefetch truth table                                          //
    // ------------------------------------------------------------------ //

    @Test
    public void testFirstCallAlwaysFetches() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 200));

        PublicKey key = cache.getPublicKey("kid-1", url1);
        assertNotNull(key);
        assertEquals(1, fetchCount.get());
    }

    @Test
    public void testAfterTtlExpiryRefetches() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response1 = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        byte[] response2 = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair2, "sig"));
        AtomicReference<byte[]> response = new AtomicReference<>(response1);
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response.get();
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 100, 0));

        PublicKey first = cache.getPublicKey("kid-1", url1);
        assertNotNull(first);
        assertEquals(1, fetchCount.get());

        Thread.sleep(150);
        response.set(response2);

        PublicKey second = cache.getPublicKey("kid-1", url1);
        assertNotNull(second);
        assertEquals(2, fetchCount.get());
    }

    @Test
    public void testKidDependentWithinTtlKnownKidNoRefetch() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertEquals(1, fetchCount.get());
    }

    @Test
    public void testKidDependentWithinTtlUnknownKidRefetches() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response1 = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        byte[] response2 = jwksBytes(
                rsaJwkJson("kid-1", rsaKeyPair1, "sig"),
                rsaJwkJson("kid-2", rsaKeyPair2, "sig"));
        AtomicReference<byte[]> response = new AtomicReference<>(response1);
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response.get();
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertEquals(1, fetchCount.get());

        response.set(response2);
        assertNotNull(cache.getPublicKey("kid-2", url1));
        assertEquals(2, fetchCount.get());
    }

    // ------------------------------------------------------------------ //
    //  Rate limiting                                                      //
    // ------------------------------------------------------------------ //

    @Test
    public void testRefetchSuppressedWithinRateLimit() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 100, 500));

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertEquals(1, fetchCount.get());

        Thread.sleep(150);

        PublicKey stale = cache.getPublicKey("kid-1", url1);
        assertNotNull(stale);
        assertEquals(1, fetchCount.get());
    }

    @Test
    public void testRefetchAllowedAfterRateLimitWindow() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 100, 200));

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertEquals(1, fetchCount.get());

        Thread.sleep(250);

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertEquals(2, fetchCount.get());
    }

    @Test
    public void testRateLimitAppliesToUnknownKidDependent() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 500));

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertEquals(1, fetchCount.get());

        assertNull(cache.getPublicKey("kid-unknown", url1));
        assertEquals(1, fetchCount.get());
    }

    // ------------------------------------------------------------------ //
    //  Failure handling                                                   //
    // ------------------------------------------------------------------ //

    @Test
    public void testFirstFetchFailureReturnsNull() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            throw new JwksException("simulated failure");
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        assertNull(cache.getPublicKey("kid-1", url1));
        assertEquals(1, fetchCount.get());
    }

    @Test
    public void testFailurePreservesStaleCacheKeys() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        AtomicBoolean shouldFail = new AtomicBoolean(false);
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            if (shouldFail.get()) {
                throw new JwksException("simulated failure");
            }
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 100, 0));

        PublicKey first = cache.getPublicKey("kid-1", url1);
        assertNotNull(first);
        assertEquals(1, fetchCount.get());

        Thread.sleep(150);
        shouldFail.set(true);

        PublicKey afterFailure = cache.getPublicKey("kid-1", url1);
        assertNotNull(afterFailure);
        assertEquals(2, fetchCount.get());
    }

    @Test
    public void testMalformedJsonPreservesStaleCacheKeys() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] validResponse = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        byte[] malformed = "not json".getBytes(StandardCharsets.UTF_8);
        AtomicReference<byte[]> response = new AtomicReference<>(validResponse);
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response.get();
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 100, 0));

        PublicKey first = cache.getPublicKey("kid-1", url1);
        assertNotNull(first);
        assertEquals(1, fetchCount.get());

        Thread.sleep(150);
        response.set(malformed);

        PublicKey afterMalformed = cache.getPublicKey("kid-1", url1);
        assertNotNull(afterMalformed);
        assertEquals(2, fetchCount.get());
    }

    @Test
    public void testFailureReturnsNullWhenPreserveStaleDisabled() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        AtomicBoolean shouldFail = new AtomicBoolean(false);
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            if (shouldFail.get()) {
                throw new JwksException("simulated failure");
            }
            return response;
        };
        JwksCache cache = new JwksCache(JwksConfig.builder()
                .fetcher(fetcher)
                .keyFilter(FOR_SIGNATURE_VALIDATION)
                .cacheTtlMs(100)
                .minTimeBetweenRequestsMs(0)
                .preserveStaleOnFailure(false)
                .build());

        PublicKey first = cache.getPublicKey("kid-1", url1);
        assertNotNull(first);
        assertEquals(1, fetchCount.get());

        Thread.sleep(150);
        shouldFail.set(true);

        PublicKey afterFailure = cache.getPublicKey("kid-1", url1);
        assertNull(afterFailure);
        assertEquals(2, fetchCount.get());
    }

    @Test
    public void testFailureWithRateLimitReturnsNullForAllKids() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        AtomicBoolean shouldFail = new AtomicBoolean(false);
        byte[] response = jwksBytes(
                rsaJwkJson("kid-1", rsaKeyPair1, "sig"),
                rsaJwkJson("kid-2", rsaKeyPair2, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            if (shouldFail.get()) {
                throw new JwksException("simulated failure");
            }
            return response;
        };
        JwksCache cache = new JwksCache(JwksConfig.builder()
                .fetcher(fetcher)
                .keyFilter(FOR_SIGNATURE_VALIDATION)
                .cacheTtlMs(150)
                .minTimeBetweenRequestsMs(300)
                .preserveStaleOnFailure(false)
                .build());

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertNotNull(cache.getPublicKey("kid-2", url1));
        assertEquals(1, fetchCount.get());

        Thread.sleep(300);
        shouldFail.set(true);

        assertNull(cache.getPublicKey("kid-1", url1));
        assertEquals(2, fetchCount.get());

        // rate-limited blocks the fetch, returns null(map's empty)
        assertNull(cache.getPublicKey("kid-2", url1));
        assertEquals(2, fetchCount.get());

        Thread.sleep(300);
        shouldFail.set(false);

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertEquals(3, fetchCount.get());
        assertNotNull(cache.getPublicKey("kid-2", url1));
        assertEquals(3, fetchCount.get());
    }

    @Test
    public void testFailureWithNoRateLimitAttemptsFreshFetch() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        AtomicBoolean shouldFail = new AtomicBoolean(false);
        byte[] response = jwksBytes(
                rsaJwkJson("kid-1", rsaKeyPair1, "sig"),
                rsaJwkJson("kid-2", rsaKeyPair2, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            if (shouldFail.get()) {
                throw new JwksException("simulated failure");
            }
            return response;
        };
        JwksCache cache = new JwksCache(JwksConfig.builder()
                .fetcher(fetcher)
                .keyFilter(FOR_SIGNATURE_VALIDATION)
                .cacheTtlMs(200)
                .minTimeBetweenRequestsMs(0)
                .preserveStaleOnFailure(false)
                .build());

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertNotNull(cache.getPublicKey("kid-2", url1));
        assertEquals(1, fetchCount.get());

        Thread.sleep(250);
        shouldFail.set(true);

        assertNull(cache.getPublicKey("kid-1", url1));
        assertEquals(2, fetchCount.get());

        assertNull(cache.getPublicKey("kid-2", url1));
        assertEquals(3, fetchCount.get());

        Thread.sleep(250);
        shouldFail.set(false);

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertEquals(4, fetchCount.get());
        assertNotNull(cache.getPublicKey("kid-2", url1));
        assertEquals(4, fetchCount.get());
    }

    @Test
    public void testFailureAdvancesTimestampPreventsRetryStorm() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        AtomicBoolean shouldFail = new AtomicBoolean(false);
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            if (shouldFail.get()) {
                throw new JwksException("simulated failure");
            }
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 200));

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertEquals(1, fetchCount.get());

        shouldFail.set(true);
        Thread.sleep(250);

        assertNull(cache.getPublicKey("kid-2", url1));
        assertEquals(2, fetchCount.get());

        assertNull(cache.getPublicKey("kid-2", url1));
        assertEquals(2, fetchCount.get());
    }

    // ------------------------------------------------------------------ //
    //  reset()                                                            //
    // ------------------------------------------------------------------ //

    @Test
    public void testResetFetchesImmediatelyBypassingRateLimit() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 5000));

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertEquals(1, fetchCount.get());

        cache.reset(url1);
        assertEquals(2, fetchCount.get());
    }

    @Test
    public void testResetOnNeverFetchedUrlDoesNotThrow() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        cache.reset(url1);
        assertEquals(1, fetchCount.get());
    }

    @Test
    public void testResetUpdatesKeysVisibleToSubsequentCall() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response1 = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        byte[] response2 = jwksBytes(
                rsaJwkJson("kid-1", rsaKeyPair1, "sig"),
                rsaJwkJson("kid-2", rsaKeyPair2, "sig"));
        AtomicReference<byte[]> response = new AtomicReference<>(response1);
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response.get();
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 5000));

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertNull(cache.getPublicKey("kid-2", url1));
        assertEquals(1, fetchCount.get());

        response.set(response2);
        cache.reset(url1);
        assertEquals(2, fetchCount.get());

        assertNotNull(cache.getPublicKey("kid-2", url1));
        assertEquals(2, fetchCount.get());
    }

    // ------------------------------------------------------------------ //
    //  getAnyKey()                                                        //
    // ------------------------------------------------------------------ //

    @Test
    public void testGetAnyKeySingleKey() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        PublicKey key = cache.getAnyKey(url1);
        assertNotNull(key);
        assertEquals(1, fetchCount.get());
    }

    @Test
    public void testGetAnyKeyMultipleKeysReturnsOne() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(
                rsaJwkJson("kid-1", rsaKeyPair1, "sig"),
                rsaJwkJson("kid-2", rsaKeyPair2, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        PublicKey key = cache.getAnyKey(url1);
        assertNotNull(key);
        assertEquals(1, fetchCount.get());
    }

    @Test
    public void testGetAnyKeyEmptyJwksReturnsNull() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes();
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        assertNull(cache.getAnyKey(url1));
        assertEquals(1, fetchCount.get());
    }

    @Test
    public void testGetAnyKeyRespectsRateLimiting() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 50, 10_000));

        PublicKey first = cache.getAnyKey(url1);
        assertNotNull(first);
        assertEquals(1, fetchCount.get());

        Thread.sleep(100);

        PublicKey second = cache.getAnyKey(url1);
        assertNotNull(second);
        assertEquals(1, fetchCount.get());
    }

    // ------------------------------------------------------------------ //
    //  Multi-URL                                                          //
    // ------------------------------------------------------------------ //

    @Test
    public void testIndependentCachesPerUrl() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response1 = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        byte[] response2 = jwksBytes(rsaJwkJson("kid-2", rsaKeyPair2, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            if (url.equals(url1)) return response1;
            return response2;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 5000));

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertNull(cache.getPublicKey("kid-1", url2));
        assertNotNull(cache.getPublicKey("kid-2", url2));
        assertNull(cache.getPublicKey("kid-2", url1));
        assertEquals(2, fetchCount.get());
    }

    @Test
    public void testFailureOnOneUrlDoesNotAffectOther() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            if (url.equals(url2)) {
                throw new JwksException("url2 down");
            }
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertNull(cache.getPublicKey("kid-1", url2));
        assertEquals(2, fetchCount.get());

        assertNotNull(cache.getPublicKey("kid-1", url1));
        assertEquals(2, fetchCount.get());
    }

    @Test
    public void testConcurrentSameUrlSingleFetch() throws Exception {
        CountDownLatch insideFetch = new CountDownLatch(1);
        CountDownLatch gate = new CountDownLatch(1);
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            insideFetch.countDown();
            try {
                gate.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new JwksException("interrupted", e);
            }
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        int threadCount = 4;
        Thread[] threads = new Thread[threadCount];
        PublicKey[] results = new PublicKey[threadCount];

        for (int i = 0; i < threadCount; i++) {
            final int idx = i;
            threads[i] = new Thread(() -> results[idx] = cache.getPublicKey("kid-1", url1));
            threads[i].start();
        }

        assertTrue("Timed out waiting for fetch to start",
                insideFetch.await(5, TimeUnit.SECONDS));
        Thread.sleep(50);
        gate.countDown();

        for (Thread t : threads) {
            t.join(5000);
        }

        assertEquals(1, fetchCount.get());
        for (int i = 0; i < threadCount; i++) {
            assertNotNull("Thread " + i + " got null", results[i]);
        }
    }


    // ------------------------------------------------------------------ //
    //  Key filtering                                                      //
    // ------------------------------------------------------------------ //

    @Test
    public void testKeyFilterRejectsAllYieldsNoKeys() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(JwksConfig.builder()
                .fetcher(fetcher)
                .keyFilter(jwk -> false)
                .cacheTtlMs(5000)
                .minTimeBetweenRequestsMs(0)
                .build());

        assertNull(cache.getPublicKey("kid-1", url1));
        assertEquals(1, fetchCount.get());
    }

    @Test
    public void testForSignatureValidationExcludesEncKeys() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-enc", rsaKeyPair1, "enc"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        assertNull(cache.getPublicKey("kid-enc", url1));
        assertEquals(1, fetchCount.get());
    }

    @Test
    public void testEcKeyP256ParsedCorrectly() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(ecJwkJson("kid-ec", ecKeyPair, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        PublicKey key = cache.getPublicKey("kid-ec", url1);
        assertNotNull(key);
        assertTrue(key instanceof ECPublicKey);
        assertEquals(1, fetchCount.get());
    }

    // ------------------------------------------------------------------ //
    //  Edge cases                                                         //
    // ------------------------------------------------------------------ //

    @Test
    public void testNullKidReturnsNullWithoutFetching() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(rsaJwkJson("kid-1", rsaKeyPair1, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        assertNull(cache.getPublicKey(null, url1));
        assertEquals(0, fetchCount.get());
    }

    @Test
    public void testJwksKeyWithoutKidDoesNotThrow() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        byte[] response = jwksBytes(
                rsaJwkJsonNoKid(rsaKeyPair1, "sig"),
                rsaJwkJson("kid-1", rsaKeyPair2, "sig"));
        JwksFetcher fetcher = url -> {
            fetchCount.incrementAndGet();
            return response;
        };
        JwksCache cache = new JwksCache(sigConfig(fetcher, 5000, 0));

        PublicKey key = cache.getPublicKey("kid-1", url1);
        assertNotNull(key);
        assertEquals(1, fetchCount.get());
    }

    // ------------------------------------------------------------------ //
    //  Test infrastructure                                                //
    // ------------------------------------------------------------------ //

    private static JwksConfig sigConfig(JwksFetcher fetcher, long ttlMs, long minTimeMs) {
        return JwksConfig.builder()
                .fetcher(fetcher)
                .keyFilter(FOR_SIGNATURE_VALIDATION)
                .cacheTtlMs(ttlMs)
                .minTimeBetweenRequestsMs(minTimeMs)
                .build();
    }

    private static byte[] jwksBytes(String... jwkJsonEntries) {
        String keys = String.join(",", jwkJsonEntries);
        return ("{\"keys\":[" + keys + "]}").getBytes(StandardCharsets.UTF_8);
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
