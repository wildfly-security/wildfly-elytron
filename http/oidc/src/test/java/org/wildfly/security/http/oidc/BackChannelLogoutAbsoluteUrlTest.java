/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.util.List;

import org.htmlunit.Page;
import org.htmlunit.WebClient;
import org.apache.http.HttpStatus;
import org.junit.Test;
import org.keycloak.representations.idm.ClientRepresentation;

public class BackChannelLogoutAbsoluteUrlTest extends AbstractLogoutTest {

    private static final String LOGOUT_CALLBACK_PATH = "/logout/callback";

    @Override
    protected OidcJsonConfiguration getClientConfiguration() {
        OidcJsonConfiguration config = super.getClientConfiguration();
        config.setLogoutCallbackPath(rewriteHost(getClientUrl()) + LOGOUT_CALLBACK_PATH);
        return config;
    }

    @Override
    protected void doConfigureClient(ClientRepresentation client) {
        List<String> redirectUris = client.getRedirectUris();
        String redirectUri = redirectUris.get(0);

        OidcClientConfiguration config = new OidcClientConfiguration();
        config.setLogoutCallbackPath(rewriteHost(redirectUri) + LOGOUT_CALLBACK_PATH);
        client.setFrontchannelLogout(false);
        client.getAttributes().put("backchannel.logout.session.required", "true");
        client.getAttributes().put("backchannel.logout.url", config.getLogoutCallbackPath());
    }

    private static String rewriteHost(String redirectUri) {
        return redirectUri.replace("localhost", "host.testcontainers.internal");
    }

    @Test
    public void testBackChannelLogout() throws Exception {
        URI requestUri = new URI(getClientUrl());
        try (WebClient webClient = getWebClient()) {
            webClient.getPage(getClientUrl());
            TestingHttpServerResponse response = getCurrentResponse();
            assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, response.getStatusCode());
            assertEquals(Status.NO_AUTH, getCurrentRequest().getResult());

            try (WebClient webClient2 = getWebClient()) {
                webClient2.getOptions().setJavaScriptEnabled(false);
                Page page = loginToKeycloak(webClient2, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                        requestUri, response.getLocation(),
                        response.getCookies())
                        .click();
                assertTrue(page.getWebResponse().getContentAsString().contains("Welcome, authenticated user"));

                // logged out after finishing the redirections during logout
                assertUserAuthenticated();
                webClient2.getOptions().setTimeout(60000); // Allow time for backchannel callback to complete
                webClient2.getPage(getLogoutUrl());
                assertUserNotAuthenticated();
            }
        }
    }
}
