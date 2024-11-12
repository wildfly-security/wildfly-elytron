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

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.QueueDispatcher;
import okhttp3.mockwebserver.RecordedRequest;
import org.apache.http.HttpStatus;
import org.junit.Test;
import org.keycloak.representations.idm.ClientRepresentation;

/**
 * Tests for the OpenID Connect authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class FrontChannelLogoutTest extends AbstractLogoutTest {

    @Override
    protected void doConfigureClient(ClientRepresentation client) {
        client.setFrontchannelLogout(true);
        List<String> redirectUris = client.getRedirectUris();
        String redirectUri = redirectUris.get(0);

        OidcClientConfiguration ocConfig = new OidcClientConfiguration();
        client.getAttributes().put("frontchannel.logout.url", redirectUri
                + ocConfig.getLogoutCallbackPath());
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
        assertUserNotAuthenticated();
    }

    @Test
    public void testRPInitiatedLogoutWithPostLogoutUri() throws Exception {
        OidcClientConfiguration oidcClientConfiguration = getClientConfig();
        oidcClientConfiguration.setPostLogoutPath("/post-logout");
        configureDispatcher(oidcClientConfiguration, new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                if (request.getPath().contains("/post-logout")) {
                    return new MockResponse()
                            .setBody("you are logged out from app");
                }
                return null;
            }
        });

        URI requestUri = new URI(getClientUrl());
        WebClient webClient = getWebClient();
        webClient.getPage(getClientUrl());
        TestingHttpServerResponse response = getCurrentResponse();
        Page page = loginToKeycloak(webClient, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD, requestUri, response.getLocation(),
                response.getCookies()).click();
        assertTrue(page.getWebResponse().getContentAsString().contains("Welcome, authenticated user"));

        assertUserAuthenticated();
        HtmlPage continueLogout = webClient.getPage(getClientUrl() + "/logout");
        page = continueLogout.getElementById("continue").click();
        assertUserNotAuthenticated();
        assertTrue(page.getWebResponse().getContentAsString().contains("you are logged out from app"));
    }

    @Test
    public void testFrontChannelLogout() throws Exception {
        try {
            URI requestUri = new URI(getClientUrl());
            WebClient webClient = getWebClient();
            webClient.getPage(getClientUrl());
            TextPage page = loginToKeycloak(webClient, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD, requestUri, getCurrentResponse().getLocation(),
                    getCurrentResponse().getCookies()).click();
            assertTrue(page.getContent().contains("Welcome, authenticated user"));

            HtmlPage logoutPage = webClient.getPage(getClientConfig().getEndSessionEndpointUrl() + "?client_id=" + CLIENT_ID);
            HtmlForm form = logoutPage.getForms().get(0);
            assertUserAuthenticated();
            form.getInputByName("confirmLogout").click();
            assertUserNotAuthenticated();
        } finally {
            client.setDispatcher(new QueueDispatcher());
        }
    }
}