/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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
import static org.junit.Assume.assumeTrue;
import static org.wildfly.security.http.oidc.Oidc.OIDC_NAME;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpStatus;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;

import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import io.restassured.RestAssured;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.QueueDispatcher;

/**
 * Tests for the OpenID Connect authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class OidcTest extends OidcBaseTest {

    @BeforeClass
    public static void startTestContainers() throws Exception {
        assumeTrue("Docker isn't available, OIDC tests will be skipped", isDockerAvailable());
        KEYCLOAK_CONTAINER = new KeycloakContainer();
        KEYCLOAK_CONTAINER.start();
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TEST_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP));
        client = new MockWebServer();
        client.start(CLIENT_PORT);
    }

    @AfterClass
    public static void generalCleanup() throws Exception {
        if (KEYCLOAK_CONTAINER != null) {
            RestAssured
                    .given()
                    .auth().oauth2(KeycloakConfiguration.getAdminAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl()))
                    .when()
                    .delete(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/admin/realms/" + TEST_REALM).then().statusCode(204);
            KEYCLOAK_CONTAINER.stop();
        }
        if (client != null) {
            client.shutdown();
        }
    }

    @BeforeClass
    public static void beforeClass() {
        System.setProperty("oidc.provider.url", KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM);
    }

    @AfterClass
    public static void afterClass() {
        System.clearProperty("oidc.provider.url");
    }

    @Test
    public void testWrongPassword() throws Exception {
        Map<String, Object> props = new HashMap<>();
        OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(getOidcConfigurationInputStream());
        OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
        oidcFactory = new OidcMechanismFactory(oidcClientContext);
        HttpServerAuthenticationMechanism mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler());

        URI requestUri = new URI(getClientUrl());
        TestingHttpServerRequest request = new TestingHttpServerRequest(null, requestUri);
        mechanism.evaluateRequest(request);
        TestingHttpServerResponse response = request.getResponse();
        assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, response.getStatusCode());
        assertEquals(Status.NO_AUTH, request.getResult());

        HtmlPage page = loginToKeycloak(KeycloakConfiguration.ALICE, "WRONG_PASSWORD", requestUri, response.getLocation(), response.getCookies()).click();
        assertTrue(page.getBody().asText().contains("Invalid username or password"));
    }

    @Test
    public void testWrongAuthServerUrl() throws Exception {
        performAuthentication(getOidcConfigurationInputStream(CLIENT_SECRET, "http://fakeauthserver/auth"), KeycloakConfiguration.ALICE,
                KeycloakConfiguration.ALICE_PASSWORD, false, -1, null, null);
    }

    @Test
    public void testWrongClientSecret() throws Exception {
        performAuthentication(getOidcConfigurationInputStream("WRONG_CLIENT_SECRET"), KeycloakConfiguration.ALICE,
                KeycloakConfiguration.ALICE_PASSWORD, true, HttpStatus.SC_FORBIDDEN, null,"Forbidden");
    }

    @Test(expected = RuntimeException.class)
    public void testMissingRequiredConfigurationOption() {
        OidcClientConfigurationBuilder.build(getOidcConfigurationMissingRequiredOption());
    }

    @Test
    public void testSucessfulAuthenticationWithAuthServerUrl() throws Exception {
        performAuthentication(getOidcConfigurationInputStream(), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSucessfulAuthenticationWithProviderUrl() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithProviderUrl(), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSucessfulAuthenticationWithProviderUrlTrailingSlash() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithProviderUrlTrailingSlash(), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSucessfulAuthenticationWithEnvironmentVariableExpression() throws Exception {
        String oidcProviderUrl = "/realms/" + TEST_REALM;
        String providerUrlEnv = System.getenv("OIDC_PROVIDER_URL_ENV");
        assertEquals(oidcProviderUrl, providerUrlEnv);

        performAuthentication(getOidcConfigurationInputStreamWithEnvironmentVariableExpression(), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSucessfulAuthenticationWithSystemPropertyExpression() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithSystemPropertyExpression(), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testTokenSignatureAlgorithm() throws Exception {
        // keycloak uses RS256
        performAuthentication(getOidcConfigurationInputStreamWithTokenSignatureAlgorithm(), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    // Note: The tests will fail if `localhost` is not listed first in `/etc/hosts` file for the loopback addresses (IPv4 and IPv6).
    private void performAuthentication(InputStream oidcConfig, String username, String password, boolean loginToKeycloak,
                                       int expectedDispatcherStatusCode, String expectedLocation, String clientPageText) throws Exception {
        try {
            Map<String, Object> props = new HashMap<>();
            OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(oidcConfig);
            assertEquals(OidcClientConfiguration.RelativeUrlsUsed.NEVER, oidcClientConfiguration.getRelativeUrls());

            OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
            oidcFactory = new OidcMechanismFactory(oidcClientContext);
            HttpServerAuthenticationMechanism mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler());

            URI requestUri = new URI(getClientUrl());
            TestingHttpServerRequest request = new TestingHttpServerRequest(null, requestUri);
            mechanism.evaluateRequest(request);
            TestingHttpServerResponse response = request.getResponse();
            assertEquals(loginToKeycloak ? HttpStatus.SC_MOVED_TEMPORARILY : HttpStatus.SC_FORBIDDEN, response.getStatusCode());
            assertEquals(Status.NO_AUTH, request.getResult());

            if (loginToKeycloak) {
                client.setDispatcher(createAppResponse(mechanism, expectedDispatcherStatusCode, expectedLocation, clientPageText));
                TextPage page = loginToKeycloak(username, password, requestUri, response.getLocation(),
                        response.getCookies()).click();
                assertTrue(page.getContent().contains(clientPageText));
            }
        } finally {
            client.setDispatcher(new QueueDispatcher());
        }
    }

    private InputStream getOidcConfigurationInputStream() {
        return getOidcConfigurationInputStream(CLIENT_SECRET);
    }

    private InputStream getOidcConfigurationInputStream(String clientSecret) {
        return getOidcConfigurationInputStream(clientSecret, KEYCLOAK_CONTAINER.getAuthServerUrl());
    }

    private InputStream getOidcConfigurationInputStream(String clientSecret, String authServerUrl) {
        String oidcConfig = "{\n" +
                "    \"realm\" : \"" + TEST_REALM + "\",\n" +
                "    \"resource\" : \"" + CLIENT_ID + "\",\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"auth-server-url\" : \"" + authServerUrl + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + clientSecret + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithProviderUrl() {
        String oidcConfig = "{\n" +
                "    \"resource\" : \"" + CLIENT_ID + "\",\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithEnvironmentVariableExpression() {
        String oidcConfig = "{\n" +
                "    \"resource\" : \"" + CLIENT_ID + "\",\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "${oidc.provider-url-env}\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithSystemPropertyExpression() {
        String oidcConfig = "{\n" +
                "    \"resource\" : \"" + CLIENT_ID + "\",\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"provider-url\" : \"${oidc.provider.url}\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithProviderUrlTrailingSlash() {
        String oidcConfig = "{\n" +
                "    \"resource\" : \"" + CLIENT_ID + "\",\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "/" + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationMissingRequiredOption() {
        String oidcConfig = "{\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithTokenSignatureAlgorithm() {
        String oidcConfig = "{\n" +
                "    \"token-signature-algorithm\" : \"RS256\",\n" +
                "    \"resource\" : \"" + CLIENT_ID + "\",\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }
}
