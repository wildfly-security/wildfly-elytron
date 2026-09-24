/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.http.bearer;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

/**
 * Tests for the bearer token pattern in {@link BearerTokenAuthenticationMechanism}.
 *
 * RFC-6750 Section 2.1 defines the b64token character set as:
 *     b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=" *1"#"
 *
 * The regex must reject characters outside this set, including injection
 * characters like '&amp;' and '='.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class BearerTokenPatternTest {

    @Test
    public void testLegitimateTokenMatches() {
        assertNotNull("A simple alphanumeric token should match",
                BearerTokenAuthenticationMechanism.extractBearerToken("Bearer eyJhbGciOiJSUzI1NiJ9"));
    }

    @Test
    public void testB64TokenSpecialCharactersMatch() {
        assertNotNull("Token with b64token special characters (-._~+/) should match",
                BearerTokenAuthenticationMechanism.extractBearerToken("Bearer abcABC012-._~+/xyz"));
    }

    @Test
    public void testBase64NoPadding() {
        assertNotNull("Token without padding should match",
                BearerTokenAuthenticationMechanism.extractBearerToken("Bearer eyJhbGciOiJSUzI1NiJ9"));
    }

    @Test
    public void testBase64SinglePadding() {
        assertNotNull("Token with single '=' padding should match",
                BearerTokenAuthenticationMechanism.extractBearerToken("Bearer eyJhbGciOiJSUzI1NiJ9="));
    }

    @Test
    public void testBase64DoublePadding() {
        assertNotNull("Token with double '==' padding should match",
                BearerTokenAuthenticationMechanism.extractBearerToken("Bearer eyJhbGciOiJSUzI1NiJ9=="));
    }

    @Test
    public void testEqualsMidTokenDoesNotMatch() {
        assertNull("'=' in the middle of a token is not valid b64token",
                BearerTokenAuthenticationMechanism.extractBearerToken("Bearer abc=def"));
    }

    @Test
    public void testTokenWithTrailingHash() {
        assertNotNull("Token ending with '#' (per b64token grammar) should match",
                BearerTokenAuthenticationMechanism.extractBearerToken("Bearer abcdef123#"));
    }

    @Test
    public void testInjectionTokenDoesNotMatch() {
        assertNull("Token containing '&' must be rejected (parameter injection)",
                BearerTokenAuthenticationMechanism.extractBearerToken("Bearer token&injected=evil"));
    }

    @Test
    public void testTokenWithAmpersandDoesNotMatch() {
        assertNull("Token containing '&' must be rejected",
                BearerTokenAuthenticationMechanism.extractBearerToken("Bearer abc&def"));
    }

    @Test
    public void testTokenWithPercentDoesNotMatch() {
        assertNull("Token containing '%' must be rejected",
                BearerTokenAuthenticationMechanism.extractBearerToken("Bearer abc%20def"));
    }

    @Test
    public void testTokenWithQuestionMarkDoesNotMatch() {
        assertNull("Token containing '?' must be rejected",
                BearerTokenAuthenticationMechanism.extractBearerToken("Bearer abc?def"));
    }

    @Test
    public void testCaseInsensitiveBearer() {
        assertNotNull("'bearer' keyword should be case-insensitive",
                BearerTokenAuthenticationMechanism.extractBearerToken("bearer eyJhbGciOiJSUzI1NiJ9"));
        assertNotNull("'BEARER' keyword should be case-insensitive",
                BearerTokenAuthenticationMechanism.extractBearerToken("BEARER eyJhbGciOiJSUzI1NiJ9"));
    }
}
