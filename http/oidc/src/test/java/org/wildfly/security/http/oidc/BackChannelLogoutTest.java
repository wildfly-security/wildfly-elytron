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

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import org.apache.http.HttpStatus;
import org.junit.Test;
import org.keycloak.representations.idm.ClientRepresentation;

public class BackChannelLogoutTest extends AbstractLogoutTest {

    @Override
    protected void doConfigureClient(ClientRepresentation client) {
        List<String> redirectUris = client.getRedirectUris();
        String redirectUri = redirectUris.get(0);

        OidcClientConfiguration config = new OidcClientConfiguration();
        client.setFrontchannelLogout(false);
        client.getAttributes().put("backchannel.logout.session.required", "true");
        client.getAttributes().put("backchannel.logout.url", rewriteHost(redirectUri)
                + config.getLogoutCallbackPath());
    }

    private static String rewriteHost(String redirectUri) {
        try {
            return redirectUri.replace("localhost", InetAddress.getLocalHost().getHostAddress());
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testRPInitiatedLogout() throws Exception {
        URI requestUri = new URI(getClientUrl());
        WebClient webClient = getWebClient();
        webClient.getPage(getClientUrl());
        TestingHttpServerResponse response = getCurrentResponse();
        assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, response.getStatusCode());
        assertEquals(Status.NO_AUTH, getCurrentRequest().getResult());

        webClient = getWebClient();
        Page page = loginToKeycloak(webClient, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                requestUri, response.getLocation(),
                response.getCookies())
                .click();
        assertTrue(page.getWebResponse().getContentAsString().contains("Welcome, authenticated user"));

        // logged out after finishing the redirections during frontchannel logout
        assertUserAuthenticated();
        webClient.getPage(getClientUrl() + getClientConfig().getLogoutPath());
        assertUserAuthenticated();
        webClient.getPage(getClientUrl());
        assertUserNotAuthenticated();
    }
}