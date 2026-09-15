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

import mockit.Expectations;
import mockit.Mocked;
import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.HttpServerRequest;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.AuthorizeCallback;
import java.util.Arrays;
import java.util.Collections;

/**
 * Test class for BearerTokenAuthenticationMechanism.
 */
public class BearerTokenAuthenticationMechanismTest {
    private CallbackHandler callbackHandler;
    private BearerTokenAuthenticationMechanism mechanism;

    @Mocked
    private HttpServerRequest request;

    @Before
    public void setUp() {
        // Prepare a callback handler that always verifies evidence and authorizes
        callbackHandler = callbacks -> {
            for (Callback callback : callbacks) {
                if (callback instanceof EvidenceVerifyCallback) {
                    ((EvidenceVerifyCallback) callback).setVerified(true);
                }
                if (callback instanceof AuthorizeCallback) {
                    ((AuthorizeCallback) callback).setAuthorized(true); // Always allow authorization
                }
            }
        };
    }

    /**
     * Test successful token extraction from cookie when fallback is enabled.
     */
    @Test
    public void testTokenExtractionFromCookie() throws Exception {
        mechanism = new BearerTokenAuthenticationMechanism(callbackHandler, true, "AUTH_TOKEN");

        new Expectations() {{
            request.getRequestHeaderValues(HttpConstants.AUTHORIZATION);
            result = null; // No Authorization header

            request.getCookies();
            result = Collections.singletonList(new SimpleHttpServerCookie("AUTH_TOKEN", "test_token"));

            // Expect successful authentication
            request.authenticationComplete();
        }};

        mechanism.evaluateRequest(request);
    }

    /**
     * Test that cookie fallback is not used when disabled.
     */
    @Test
    public void testCookieFallbackDisabled() throws Exception {
        mechanism = new BearerTokenAuthenticationMechanism(callbackHandler, false, "AUTH_TOKEN");

        new Expectations() {{
            request.getRequestHeaderValues(HttpConstants.AUTHORIZATION);
            result = null; // No Authorization header

            // Should not query cookies
            request.getCookies(); times = 0;

            // Expect no authentication in progress
            request.noAuthenticationInProgress(withNotNull());
        }};

        mechanism.evaluateRequest(request);
    }

    /**
     * Test prioritization of Authorization header over cookie.
     */
    @Test
    public void testHeaderPriorityOverCookie() throws Exception {
        mechanism = new BearerTokenAuthenticationMechanism(callbackHandler, true, "AUTH_TOKEN");

        new Expectations() {{
            request.getRequestHeaderValues(HttpConstants.AUTHORIZATION);
            result = Collections.singletonList("Bearer header_token");

            // Should not query cookies
            request.getCookies(); times = 0;

            // Expect successful authentication
            request.authenticationComplete();
        }};

        mechanism.evaluateRequest(request);
    }

    /**
     * Test custom cookie name handling.
     */
    @Test
    public void testCustomCookieNameHandling() throws Exception {
        mechanism = new BearerTokenAuthenticationMechanism(callbackHandler, true, "CUSTOM_TOKEN");

        new Expectations() {{
            request.getRequestHeaderValues(HttpConstants.AUTHORIZATION);
            result = null; // No header

            request.getCookies();
            result = Arrays.asList(
                    new SimpleHttpServerCookie("WRONG_COOKIE", "wrong_token"),
                    new SimpleHttpServerCookie("CUSTOM_TOKEN", "correct_token")
            );

            // Expect successful authentication
            request.authenticationComplete();
        }};

        mechanism.evaluateRequest(request);
    }

    /**
     * Test missing token in both header and cookie.
     */
    @Test
    public void testMissingToken() throws Exception {
        mechanism = new BearerTokenAuthenticationMechanism(callbackHandler, true, "AUTH_TOKEN");

        new Expectations() {{
            request.getRequestHeaderValues(HttpConstants.AUTHORIZATION);
            result = null; // No header

            request.getCookies();
            result = Collections.emptyList(); // No relevant cookies

            // Expect no authentication in progress
            request.noAuthenticationInProgress(withNotNull());
        }};

        mechanism.evaluateRequest(request);
    }

    /**
     * Test token verification failure.
     */
    @Test
    public void testTokenVerificationFailed() throws Exception {
        // Special callback handler for failed verification
        CallbackHandler failingHandler = callbacks -> {
            for (Callback callback : callbacks) {
                if (callback instanceof EvidenceVerifyCallback) {
                    ((EvidenceVerifyCallback) callback).setVerified(false);
                }
            }
        };

        mechanism = new BearerTokenAuthenticationMechanism(failingHandler, true, "AUTH_TOKEN");

        new Expectations() {{
            request.getRequestHeaderValues(HttpConstants.AUTHORIZATION);
            result = Collections.singletonList("Bearer invalid_token");

            // Expect authentication failure
            request.authenticationFailed(anyString, withNotNull());
        }};

        mechanism.evaluateRequest(request);
    }

    // Helper class for cookie mocking
    private static class SimpleHttpServerCookie implements HttpServerCookie {
        private final String name;
        private final String value;

        SimpleHttpServerCookie(String name, String value) {
            this.name = name;
            this.value = value;
        }

        @Override public String getName() {
            return name;
        }
        @Override public String getValue() {
            return value;
        }
        @Override public String getDomain() {
            return null;
        }
        @Override public String getPath() {
            return null;
        }
        @Override public int getMaxAge() {
            return 0;
        }
        @Override public boolean isSecure() {
            return false;
        }
        @Override public int getVersion() {
            return 0;
        }
        @Override public boolean isHttpOnly() {
            return false;
        }
    }
}