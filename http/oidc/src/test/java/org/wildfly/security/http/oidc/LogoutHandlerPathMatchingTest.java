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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Tests for {@link LogoutHandler} logout path matching.
 */
public class LogoutHandlerPathMatchingTest {

    private static final String REQUEST_PATH = "/simple-webapp-oidc/more/myCallback";

    @Test
    public void testMatchesAbsoluteLogoutCallbackUri() {
        assertTrue(LogoutHandler.matchesLogoutCallbackPath(REQUEST_PATH,
                "http://localhost:8090/simple-webapp-oidc/more/myCallback"));
    }

    @Test
    public void testMatchesRelativeLogoutCallbackPath() {
        assertTrue(LogoutHandler.matchesLogoutCallbackPath("/more/myCallback", "/more/myCallback"));
    }

    @Test
    public void testDoesNotMatchPathOnlyWithoutLeadingSlash() {
        assertFalse(LogoutHandler.matchesLogoutCallbackPath(REQUEST_PATH, "more/myCallback"));
    }

    @Test
    public void testDoesNotMatchUnrelatedPath() {
        assertFalse(LogoutHandler.matchesLogoutCallbackPath("/simple-webapp-oidc/secured",
                "http://localhost:8090/simple-webapp-oidc/more/myCallback"));
    }

    @Test
    public void testDoesNotMatchSuffixOnly() {
        assertFalse(LogoutHandler.matchesLogoutCallbackPath("/prefix/more/myCallback",
                "/more/myCallback"));
    }

    @Test
    public void testDoesNotMatchWhenConfiguredPathIsNull() {
        assertFalse(LogoutHandler.matchesLogoutCallbackPath(REQUEST_PATH, null));
    }

    @Test
    public void testDoesNotMatchWhenRequestPathIsNull() {
        assertFalse(LogoutHandler.matchesLogoutCallbackPath(null,
                "http://localhost:8090/simple-webapp-oidc/more/myCallback"));
    }

    @Test
    public void testDoesNotMatchWhenRequestPathIsEmpty() {
        assertFalse(LogoutHandler.matchesLogoutCallbackPath("",
                "http://localhost:8090/simple-webapp-oidc/more/myCallback"));
    }

    @Test
    public void testExtractPathFromAbsoluteUri() {
        assertEquals("/simple-webapp-oidc/more/myCallback",
                LogoutHandler.extractPathFromLogoutCallbackConfiguration(
                        "http://localhost:8090/simple-webapp-oidc/more/myCallback"));
    }

    @Test
    public void testExtractPathFromRelativePath() {
        assertEquals("/more/myCallback",
                LogoutHandler.extractPathFromLogoutCallbackConfiguration("/more/myCallback"));
    }

    @Test
    public void testDoesNotExtractPathFromMalformedAbsoluteUri() {
        assertNull(
                LogoutHandler.extractPathFromLogoutCallbackConfiguration("http://[malformed"));
    }

    @Test
    public void testDoesNotMatchMalformedAbsoluteUriConfiguration() {
        assertFalse(LogoutHandler.matchesLogoutCallbackPath(REQUEST_PATH, "http://[malformed"));
    }

    @Test
    public void testMatchesLogoutPath() {
        assertTrue(LogoutHandler.matchesLogoutPath("/logout", "/logout"));
    }

    @Test
    public void testDoesNotMatchLogoutPathBySuffixOnly() {
        assertFalse(LogoutHandler.matchesLogoutPath("/prefix/logout", "/logout"));
    }

    @Test
    public void testDoesNotMatchLogoutPathWhenConfiguredPathIsSuffixOfRequest() {
        assertFalse(LogoutHandler.matchesLogoutPath("/logout", "/out"));
    }

    @Test
    public void testDoesNotMatchLogoutPathWhenConfiguredPathIsNull() {
        assertFalse(LogoutHandler.matchesLogoutPath("/logout", null));
    }

    @Test
    public void testDoesNotMatchLogoutPathWhenRequestPathIsNull() {
        assertFalse(LogoutHandler.matchesLogoutPath(null, "/logout"));
    }

    @Test
    public void testDoesNotMatchLogoutPathWhenRequestPathIsEmpty() {
        assertFalse(LogoutHandler.matchesLogoutPath("", "/logout"));
    }
}
