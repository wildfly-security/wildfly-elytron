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
import static org.junit.Assert.assertNull;

import org.junit.Test;

/**
 * Tests logout path configuration validation in {@link OidcClientConfigurationBuilder}.
 */
public class OidcClientConfigurationBuilderLogoutPathTest {

    private static final String LOGOUT_PATH = "/logout";
    private static final String LOGOUT_CALLBACK_PATH = "/logout/callback";

    @Test
    public void testLogoutCallbackPathAcceptsAbsoluteUri() {
        OidcJsonConfiguration config = logoutConfiguration();
        config.setLogoutCallbackPath("http://localhost:8090/app/logout/callback");

        OidcClientConfiguration built = OidcClientConfigurationBuilder.build(config);

        assertEquals("http://localhost:8090/app/logout/callback", built.getLogoutCallbackPath());
    }

    @Test
    public void testLogoutCallbackPathAcceptsRelativePath() {
        OidcJsonConfiguration config = logoutConfiguration();
        config.setLogoutCallbackPath(LOGOUT_CALLBACK_PATH);

        OidcClientConfiguration built = OidcClientConfigurationBuilder.build(config);

        assertEquals(LOGOUT_CALLBACK_PATH, built.getLogoutCallbackPath());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testLogoutCallbackPathRejectsMalformedAbsoluteUri() {
        OidcJsonConfiguration config = logoutConfiguration();
        config.setLogoutCallbackPath("http://[malformed");

        OidcClientConfigurationBuilder.build(config);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testLogoutCallbackPathRejectsPathWithoutLeadingSlash() {
        OidcJsonConfiguration config = logoutConfiguration();
        config.setLogoutCallbackPath("logout/callback");

        OidcClientConfigurationBuilder.build(config);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testLogoutPathRejectsValueWithoutLeadingSlash() {
        OidcJsonConfiguration config = logoutConfiguration();
        config.setLogoutPath("logout");

        OidcClientConfigurationBuilder.build(config);
    }

    @Test
    public void testLogoutPathsUnsetWhenLogoutNotConfigured() {
        OidcJsonConfiguration config = baseConfiguration();

        OidcClientConfiguration built = OidcClientConfigurationBuilder.build(config);

        assertNull(built.getLogoutPath());
        assertNull(built.getLogoutCallbackPath());
        assertNull(built.getPostLogoutRedirectUri());
    }

    @Test
    public void testLogoutConfiguredWithExplicitPathsOnly() {
        OidcJsonConfiguration config = logoutConfiguration();
        config.setLogoutPath("/custom-logout");
        config.setLogoutCallbackPath("/custom-callback");

        OidcClientConfiguration built = OidcClientConfigurationBuilder.build(config);

        assertEquals("/custom-logout", built.getLogoutPath());
        assertEquals("/custom-callback", built.getLogoutCallbackPath());
        assertNull(built.getPostLogoutRedirectUri());
    }

    @Test
    public void testPostLogoutRedirectUriOptionalWhenPathsSet() {
        OidcJsonConfiguration config = logoutConfiguration();
        config.setPostLogoutRedirectUri("http://localhost:8090/app/");

        OidcClientConfiguration built = OidcClientConfigurationBuilder.build(config);

        assertEquals(LOGOUT_PATH, built.getLogoutPath());
        assertEquals(LOGOUT_CALLBACK_PATH, built.getLogoutCallbackPath());
        assertEquals("http://localhost:8090/app/", built.getPostLogoutRedirectUri());
    }

    @Test
    public void testLogoutCallbackPathOptionalWhenOnlyLogoutPathSet() {
        OidcJsonConfiguration config = baseConfiguration();
        config.setLogoutPath("/custom-logout");

        OidcClientConfiguration built = OidcClientConfigurationBuilder.build(config);

        assertEquals("/custom-logout", built.getLogoutPath());
        assertNull(built.getLogoutCallbackPath());
    }

    @Test
    public void testLogoutPathOptionalWhenOnlyLogoutCallbackPathSet() {
        OidcJsonConfiguration config = baseConfiguration();
        config.setLogoutCallbackPath(LOGOUT_CALLBACK_PATH);
        OidcClientConfiguration built = OidcClientConfigurationBuilder.build(config);

        assertNull(built.getLogoutPath());
        assertEquals("/logout/callback", built.getLogoutCallbackPath());
    }

    @Test
    public void testLogoutCallbackPathOptionalWhenOnlyPostLogoutRedirectUriSet() {
        OidcJsonConfiguration config = baseConfiguration();
        config.setPostLogoutRedirectUri("http://localhost:8090/app/");

        OidcClientConfiguration built = OidcClientConfigurationBuilder.build(config);

        assertNull(built.getLogoutPath());
        assertNull(built.getLogoutCallbackPath());
        assertEquals("http://localhost:8090/app/", built.getPostLogoutRedirectUri());
    }

    private static OidcJsonConfiguration logoutConfiguration() {
        OidcJsonConfiguration config = baseConfiguration();
        config.setLogoutPath(LOGOUT_PATH);
        config.setLogoutCallbackPath(LOGOUT_CALLBACK_PATH);
        return config;
    }

    private static OidcJsonConfiguration baseConfiguration() {
        OidcJsonConfiguration config = new OidcJsonConfiguration();
        config.setClientId("test-client");
        config.setProviderUrl("http://localhost:8080/realms/test");
        config.setPublicClient(true);
        return config;
    }
}
