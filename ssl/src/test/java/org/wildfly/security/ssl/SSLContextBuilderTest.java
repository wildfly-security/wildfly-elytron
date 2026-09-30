/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.ssl;

import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * Tests for {@link SSLContextBuilder} configuration validation.
 */
public class SSLContextBuilderTest {

    @Test
    public void negativeResponseTimeoutRejected() {
        try {
            new SSLContextBuilder().setResponseTimeout(-1);
            fail("Expected IllegalArgumentException for a negative response timeout");
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }

    @Test
    public void negativeCacheSizeRejected() {
        try {
            new SSLContextBuilder().setCacheSize(-1);
            fail("Expected IllegalArgumentException for a negative cache size");
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }

    @Test
    public void negativeCacheLifetimeRejected() {
        try {
            new SSLContextBuilder().setCacheLifetime(-1);
            fail("Expected IllegalArgumentException for a negative cache lifetime");
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }

    @Test
    public void zeroOcspStaplingValuesAreLegal() {
        // 0 is a valid value for these OCSP stapling settings and must not be rejected.
        new SSLContextBuilder()
                .setResponseTimeout(0)
                .setCacheSize(0)
                .setCacheLifetime(0);
    }
}
