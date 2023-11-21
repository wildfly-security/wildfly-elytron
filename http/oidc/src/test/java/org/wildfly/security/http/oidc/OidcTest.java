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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.CHARLIE;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.CHARLIE_PASSWORD;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.DAN;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.DAN_PASSWORD;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.TENANT1_PASSWORD;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.TENANT1_USER;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.TENANT2_PASSWORD;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.TENANT2_USER;
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
import com.gargoylesoftware.htmlunit.WebClient;
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

    // setting a high number for the token lifespan so we can test that a valid token from tenant1 can't be used for tenant2
    private static final int ACCESS_TOKEN_LIFESPAN = 120;
    private static final int SESSION_MAX_LIFESPAN = 120;

    @BeforeClass
    public static void startTestContainers() throws Exception {
        assumeTrue("Docker isn't available, OIDC tests will be skipped", isDockerAvailable());
        KEYCLOAK_CONTAINER = new KeycloakContainer();
        KEYCLOAK_CONTAINER.start();
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TEST_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP));
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TENANT1_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP, ACCESS_TOKEN_LIFESPAN, SESSION_MAX_LIFESPAN, true));
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TENANT2_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP, ACCESS_TOKEN_LIFESPAN, SESSION_MAX_LIFESPAN, true));
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
            RestAssured
                    .given()
                    .auth().oauth2(KeycloakConfiguration.getAdminAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl()))
                    .when()
                    .delete(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/admin/realms/" + TENANT1_REALM).then().statusCode(204);
            RestAssured
                    .given()
                    .auth().oauth2(KeycloakConfiguration.getAdminAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl()))
                    .when()
                    .delete(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/admin/realms/" + TENANT2_REALM).then().statusCode(204);
            KEYCLOAK_CONTAINER.stop();
        }
        if (client != null) {
            client.shutdown();
        }
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
        loginToAppMultiTenancy(getOidcConfigurationInputStream(CLIENT_SECRET, "http://fakeauthserver/auth"), KeycloakConfiguration.ALICE,
                KeycloakConfiguration.ALICE_PASSWORD, false, -1, null, null);
    }

    @Test(expected = RuntimeException.class)
    public void testMissingRequiredConfigurationOption() {
        OidcClientConfigurationBuilder.build(getOidcConfigurationMissingRequiredOption());
    }

    @Test
    public void testSucessfulAuthenticationWithAuthServerUrl() throws Exception {
        loginToAppMultiTenancy(getOidcConfigurationInputStream(), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSucessfulAuthenticationWithProviderUrl() throws Exception {
        loginToAppMultiTenancy(getOidcConfigurationInputStreamWithProviderUrl(), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSucessfulAuthenticationWithProviderUrlTrailingSlash() throws Exception {
        loginToAppMultiTenancy(getOidcConfigurationInputStreamWithProviderUrlTrailingSlash(), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testTokenSignatureAlgorithm() throws Exception {
        // keycloak uses RS256
        loginToAppMultiTenancy(getOidcConfigurationInputStreamWithTokenSignatureAlgorithm(), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    /*****************************************************************************************************************************************
     * Tests for multi-tenancy.
     *
     * The tests below involve two tenants:
     * Tenant1: http://localhost:5002/clientApp/tenant1
     * Tenant2: http://localhost:5002/clientApp/tenant2
     *
     * Tenant1 is secured using the tenant1 Keycloak Realm which contains the following users:
     * tenant1_user
     * charlie
     * dan
     *
     * Tenant2 is secured using the tenant2 Keycloak Realm which contains the following users:
     * tenant2_user
     * charlie
     * dan
     *
     * The first set of tests will make use of Keycloak-specific OIDC configuration.
     * The second set of tests will make use of a provider-url in the OIDC configuration.
     *****************************************************************************************************************************************/

    /**********************************************************
     * 1. Tests using Keycloak-specific OIDC configuration
     **********************************************************/

    /**
     * Test that logging into each tenant with a non-existing user fails.
     */
    @Test
    public void testNonExistingUserWithAuthServerUrl() throws Exception {
        testNonExistingUserWithAuthServerUrl(TENANT2_USER, TENANT2_PASSWORD, TENANT1_ENDPOINT);
        testNonExistingUserWithAuthServerUrl(TENANT1_USER, TENANT1_PASSWORD, TENANT2_ENDPOINT);
        testNonExistingUserWithAuthServerUrl(KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD, TENANT1_ENDPOINT);
    }

    /**
     * Test successfully logging into /tenant1 with the tenant1_user and successfully logging into /tenant2 with the tenant2_user.
     */
    @Test
    public void testSuccessfulAuthenticationWithAuthServerUrl() throws Exception {
        performTenantRequestWithAuthServerUrl(TENANT1_USER, TENANT1_PASSWORD, TENANT1_ENDPOINT, null);
        performTenantRequestWithAuthServerUrl(TENANT2_USER, TENANT2_PASSWORD, TENANT2_ENDPOINT, null);
    }

    /**
     * Test successfully logging into /tenant1 with the tenant1_user and then attempt to access /tenant1 again.
     * We should be able to access /tenant1 again without needing to log in again.
     *
     * Then test successfully logging into /tenant2 with the tenant2_user and then attempt to access /tenant2 again.
     * We should be able to access /tenant2 again without needing to log in again.
     */
    @Test
    public void testLoggedInUserWithAuthServerUrl() throws Exception {
        performTenantRequestWithAuthServerUrl(TENANT1_USER, TENANT1_PASSWORD, TENANT1_ENDPOINT, TENANT1_ENDPOINT);
        performTenantRequestWithAuthServerUrl(TENANT2_USER, TENANT2_PASSWORD, TENANT2_ENDPOINT, TENANT2_ENDPOINT);
    }

    /**
     * Test logging into /tenant1 with the tenant1_user and then attempt to access /tenant2.
     * We should be redirected to Keycloak to log in since the user's cached token isn't valid for
     * /tenant2.
     *
     * Then test logging into /tenant2 with the tenant2_user and then attempt to access /tenant1.
     * We should be redirected to Keycloak to log in since the user's cached token isn't valid for
     * /tenant1.
     */
    @Test
    public void testUnauthorizedAccessWithAuthServerUrl() throws Exception {
        performTenantRequestWithAuthServerUrl(TENANT1_USER, TENANT1_PASSWORD, TENANT1_ENDPOINT, TENANT2_ENDPOINT);
        performTenantRequestWithAuthServerUrl(TENANT2_USER, TENANT2_PASSWORD, TENANT2_ENDPOINT, TENANT1_ENDPOINT);
    }

    /**
     * Test logging into /tenant1 with a username that exists in both tenant realms and then attempt to access /tenant2.
     * We should be redirected to Keycloak to log in since the user's cached token isn't valid for /tenant2.
     *
     * Test logging into /tenant2 with a username that exists in both tenant realms and then attempt to access /tenant1.
     * We should be redirected to Keycloak to log in since the user's cached token isn't valid for /tenant1.
     */
    @Test
    public void testUnauthorizedAccessWithAuthServerUrlValidUser() throws Exception {
        performTenantRequestWithAuthServerUrl(CHARLIE, CHARLIE_PASSWORD, TENANT1_ENDPOINT, TENANT2_ENDPOINT);
        performTenantRequestWithAuthServerUrl(DAN, DAN_PASSWORD, TENANT2_ENDPOINT, TENANT1_ENDPOINT);
    }

    /**********************************************************
     * 2. Tests using a provider-url in the OIDC configuration
     **********************************************************/

    /**
     * Test that logging into each tenant with a non-existing user fails.
     */
    @Test
    public void testNonExistingUserWithProviderUrl() throws Exception {
        testNonExistingUserWithProviderUrl(TENANT2_USER, TENANT2_PASSWORD, TENANT1_ENDPOINT);
        testNonExistingUserWithProviderUrl(TENANT1_USER, TENANT1_PASSWORD, TENANT2_ENDPOINT);
        testNonExistingUserWithProviderUrl(KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD, TENANT1_ENDPOINT);
    }

    /**
     * Test successfully logging into /tenant1 with the tenant1_user and successfully logging into /tenant2 with the tenant2_user.
     */
    @Test
    public void testSuccessfulAuthenticationWithProviderUrl() throws Exception {
        performTenantRequestWithProviderUrl(TENANT1_USER, TENANT1_PASSWORD, TENANT1_ENDPOINT, null);
        performTenantRequestWithProviderUrl(TENANT2_USER, TENANT2_PASSWORD, TENANT2_ENDPOINT, null);
    }

    /**
     * Test successfully logging into /tenant1 with the tenant1_user and then attempt to access /tenant1 again.
     * We should be able to access /tenant1 again without needing to log in again.
     *
     * Then test successfully logging into /tenant2 with the tenant2_user and then attempt to access /tenant2 again.
     * We should be able to access /tenant2 again without needing to log in again.
     */
    @Test
    public void testLoggedInUserWithProviderUrl() throws Exception {
        performTenantRequestWithProviderUrl(TENANT1_USER, TENANT1_PASSWORD, TENANT1_ENDPOINT, TENANT1_ENDPOINT);
        performTenantRequestWithProviderUrl(TENANT2_USER, TENANT2_PASSWORD, TENANT2_ENDPOINT, TENANT2_ENDPOINT);
    }

    /**
     * Test logging into /tenant1 with the tenant1_user and then attempt to access /tenant2.
     * We should be redirected to Keycloak to log in since the user's cached token isn't valid for
     * /tenant2.
     *
     * Then test logging into /tenant2 with the tenant2_user and then attempt to access /tenant1.
     * We should be redirected to Keycloak to log in since the user's cached token isn't valid for
     * /tenant1.
     */
    @Test
    public void testUnauthorizedAccessWithProviderUrl() throws Exception {
        performTenantRequestWithProviderUrl(TENANT1_USER, TENANT1_PASSWORD, TENANT1_ENDPOINT, TENANT2_ENDPOINT);
        performTenantRequestWithProviderUrl(TENANT2_USER, TENANT2_PASSWORD, TENANT2_ENDPOINT, TENANT1_ENDPOINT);
    }

    /**
     * Test logging into /tenant1 with a username that exists in both tenant realms and then attempt to access /tenant2.
     * We should be redirected to Keycloak to log in since the user's cached token isn't valid for /tenant2.
     *
     * Test logging into /tenant2 with a username that exists in both tenant realms and then attempt to access /tenant1.
     * We should be redirected to Keycloak to log in since the user's cached token isn't valid for /tenant1.
     */
    @Test
    public void testUnauthorizedAccessWithProviderUrlValidUser() throws Exception {
        performTenantRequestWithProviderUrl(CHARLIE, CHARLIE_PASSWORD, TENANT1_ENDPOINT, TENANT2_ENDPOINT);
        performTenantRequestWithProviderUrl(DAN, DAN_PASSWORD, TENANT2_ENDPOINT, TENANT1_ENDPOINT);
    }

    private void testNonExistingUserWithAuthServerUrl(String username, String password, String tenant) throws Exception {
        testNonExistingUser(username, password, tenant, true);
    }

    private void testNonExistingUserWithProviderUrl(String username, String password, String tenant) throws Exception {
        testNonExistingUser(username, password, tenant, false);
    }

    private void testNonExistingUser(String username, String password, String tenant, boolean useAuthServerUrl) throws Exception {
        Map<String, Object> props = new HashMap<>();
        MultiTenantResolver multiTenantResolver = new MultiTenantResolver(useAuthServerUrl);
        OidcClientContext oidcClientContext = new OidcClientContext(multiTenantResolver);
        oidcFactory = new OidcMechanismFactory(oidcClientContext);
        HttpServerAuthenticationMechanism mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler());

        URI requestUri = new URI(getClientUrlForTenant(tenant));
        TestingHttpServerRequest request = new TestingHttpServerRequest(null, requestUri);
        mechanism.evaluateRequest(request);
        TestingHttpServerResponse response = request.getResponse();
        assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, response.getStatusCode());
        assertEquals(Status.NO_AUTH, request.getResult());

        HtmlPage page = loginToKeycloak(username, password, requestUri, response.getLocation(), response.getCookies()).click();
        assertTrue(page.getBody().asText().contains("Invalid username or password"));
    }

    private void loginToAppMultiTenancy(InputStream oidcConfig, String username, String password, boolean loginToKeycloak,
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

    private void performTenantRequestWithAuthServerUrl(String username, String password, String tenant, String otherTenant) throws Exception {
        performTenantRequest(username, password, tenant, otherTenant, true);
    }

    private void performTenantRequestWithProviderUrl(String username, String password, String tenant, String otherTenant) throws Exception {
        performTenantRequest(username, password, tenant, otherTenant, false);
    }

    private void performTenantRequest(String username, String password, String tenant, String otherTenant, boolean useAuthServerUrl) throws Exception {
        try {
            Map<String, Object> props = new HashMap<>();
            Map<String, Object> sessionScopeAttachments = new HashMap<>();
            String clientPageText = getClientPageTestForTenant(tenant);
            String expectedLocation = getClientUrlForTenant(tenant);

            // the resolver will be used to obtain the OIDC configuration
            MultiTenantResolver multiTenantResolver = new MultiTenantResolver(useAuthServerUrl);
            OidcClientContext oidcClientContext = new OidcClientContext(multiTenantResolver);

            oidcFactory = new OidcMechanismFactory(oidcClientContext);
            HttpServerAuthenticationMechanism mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler());

            // attempt to access the specified tenant, we should be redirected to Keycloak to login
            URI requestUri = new URI(getClientUrlForTenant(tenant));
            TestingHttpServerRequest request = new TestingHttpServerRequest(null, requestUri);
            mechanism.evaluateRequest(request);
            TestingHttpServerResponse response = request.getResponse();
            assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, response.getStatusCode());
            assertEquals(Status.NO_AUTH, request.getResult());

            // log into Keycloak, we should then be redirected back to the tenant upon successful authentication
            client.setDispatcher(createAppResponse(mechanism, HttpStatus.SC_MOVED_TEMPORARILY, expectedLocation, clientPageText, sessionScopeAttachments));
            TextPage page = loginToKeycloak(username, password, requestUri, response.getLocation(),
                    response.getCookies()).click();
            assertTrue(page.getContent().contains(clientPageText));

            if (otherTenant != null) {
                // attempt to access the other tenant
                client.setDispatcher(createAppResponse(mechanism, clientPageText, sessionScopeAttachments, otherTenant, tenant.equals(otherTenant)));
                WebClient webClient = getWebClient();
                page = webClient.getPage(getClientUrlForTenant(otherTenant));
                if (otherTenant.equals(tenant)) {
                    // accessing the same tenant as above, already logged in
                    assertTrue(page.getContent().contains(clientPageText));
                } else {
                    assertFalse(page.getContent().contains(clientPageText));
                }
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


    static InputStream getTenantConfigWithAuthServerUrl(String tenant) {
        String oidcConfig = "{\n" +
                "    \"realm\" : \"" + tenant + "\",\n" +
                "    \"resource\" : \"" + CLIENT_ID + "\",\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"auth-server-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    static InputStream getTenantConfigWithProviderUrl(String tenant) {
        String oidcConfig = "{\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + tenant + "\",\n" +
                "    \"client-id\" : \"" + CLIENT_ID + "\",\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private static final String getClientPageTestForTenant(String tenant) {
        return tenant.equals(TENANT1_ENDPOINT) ? TENANT1_ENDPOINT : TENANT2_ENDPOINT + ":" + CLIENT_PAGE_TEXT;
    }
}