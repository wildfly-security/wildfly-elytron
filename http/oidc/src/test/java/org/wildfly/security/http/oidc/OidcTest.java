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
import static org.wildfly.security.http.oidc.KeycloakConfiguration.KEYSTORE_CLASSPATH;
import static org.wildfly.security.http.oidc.Oidc.OIDC_NAME;
import static org.wildfly.security.http.oidc.Oidc.OIDC_SCOPE;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_TYPE_OAUTH2;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_TYPE_REQUEST;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_TYPE_REQUEST_URI;
import static org.wildfly.security.http.oidc.Oidc.NONE;
import static org.wildfly.security.http.oidc.Oidc.RSA1_5;
import static org.wildfly.security.http.oidc.Oidc.RSA_OAEP;
import static org.wildfly.security.http.oidc.Oidc.RSA_OAEP_256;
import static org.wildfly.security.http.oidc.Oidc.A128CBC_HS256;
import static org.wildfly.security.http.oidc.Oidc.A192CBC_HS384;
import static org.wildfly.security.http.oidc.Oidc.A256CBC_HS512;
import static org.wildfly.security.http.oidc.Oidc.RS_256;
import static org.wildfly.security.http.oidc.Oidc.RS_512;
import static org.wildfly.security.http.oidc.Oidc.PS_256;
import static org.wildfly.security.http.oidc.Oidc.KEYSTORE_PASS;
import static org.wildfly.security.http.oidc.Oidc.JKS_KEYSTORE_TYPE;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.QueueDispatcher;
import org.apache.http.HttpStatus;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;

import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import io.restassured.RestAssured;

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

    @Test
    public void testOpenIDWithOauth2Request() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_TYPE_OAUTH2, "", "", ""), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testOpenIDWithPlaintextRequest() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_TYPE_REQUEST, NONE, "", ""), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testOpenIDWithPlaintextEncryptedRequest() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_TYPE_REQUEST, NONE, RSA_OAEP, A128CBC_HS256), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testOpenIDWithRsaSignedAndEncryptedRequest() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_TYPE_REQUEST, RS_512, RSA_OAEP, A192CBC_HS384, KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, JKS_KEYSTORE_TYPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testOpenIDWithPsSignedAndRsaEncryptedRequest() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_TYPE_REQUEST, PS_256, RSA_OAEP_256, A256CBC_HS512, KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, JKS_KEYSTORE_TYPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testOpenIDWithInvalidSignAlgorithm() throws Exception {
        //RSNULL is a valid signature algorithm, but not one of the ones supported by keycloak
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_TYPE_REQUEST, "RSNULL", RSA1_5, A256CBC_HS512, KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, JKS_KEYSTORE_TYPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT, true);
    }

    @Test
    public void testOpenIDWithRsaSignedRequest() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_TYPE_REQUEST, RS_256, "", "", KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, JKS_KEYSTORE_TYPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testOpenIDWithPsSignedRequest() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_TYPE_REQUEST, PS_256, "", "", KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, JKS_KEYSTORE_TYPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }
    @Test
    public void testOpenIDWithInvalidRequestEncryptionAlgorithm() throws Exception {
        // None is not a valid algorithm for encrypting jwt's and RSA-OAEP is not a valid algorithm for signing
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_TYPE_REQUEST, RSA_OAEP, NONE, NONE, KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, JKS_KEYSTORE_TYPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT, true);
    }

    @Test
    public void testOpenIDWithPlaintextRequestUri() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_TYPE_REQUEST_URI, NONE, "", ""), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testOpenIDWithSignedAndEncryptedRequestUri() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_TYPE_REQUEST_URI, RS_256, RSA_OAEP_256, A256CBC_HS512, KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, JKS_KEYSTORE_TYPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    private void performAuthentication(InputStream oidcConfig, String username, String password, boolean loginToKeycloak,
                                       int expectedDispatcherStatusCode, String expectedLocation, String clientPageText) throws Exception {
        performAuthentication(oidcConfig, username, password, loginToKeycloak, expectedDispatcherStatusCode, expectedLocation, clientPageText, null, false);
    }

    private void performAuthentication(InputStream oidcConfig, String username, String password, boolean loginToKeycloak,
                                       int expectedDispatcherStatusCode, String expectedLocation, String clientPageText, String expectedScope, boolean checkInvalidScopeError) throws Exception {
        performAuthentication(oidcConfig, username, password, loginToKeycloak, expectedDispatcherStatusCode, expectedLocation, clientPageText, expectedScope, checkInvalidScopeError, false);
    }

    private void performAuthentication(InputStream oidcConfig, String username, String password, boolean loginToKeycloak,
                                       int expectedDispatcherStatusCode, String expectedLocation, String clientPageText, boolean checkInvalidRequestAlgorithm) throws Exception {
        performAuthentication(oidcConfig, username, password, loginToKeycloak, expectedDispatcherStatusCode, expectedLocation, clientPageText, null, false, checkInvalidRequestAlgorithm);
    }

    private void performAuthentication(InputStream oidcConfig, String username, String password, boolean loginToKeycloak,
                                       int expectedDispatcherStatusCode, String expectedLocation, String clientPageText, String expectedScope, boolean checkInvalidScopeError, boolean checkInvalidRequestAlgorithm) throws Exception {
        try {
            Map<String, Object> props = new HashMap<>();
            OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(oidcConfig);
            assertEquals(OidcClientConfiguration.RelativeUrlsUsed.NEVER, oidcClientConfiguration.getRelativeUrls());

            OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
            oidcFactory = new OidcMechanismFactory(oidcClientContext);
            HttpServerAuthenticationMechanism mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler());

            URI requestUri = new URI(getClientUrl());
            TestingHttpServerRequest request = new TestingHttpServerRequest(null, requestUri);
            try {
                mechanism.evaluateRequest(request);
            } catch (Exception e) {
                if (checkInvalidRequestAlgorithm) {
                    assertTrue(e.getMessage().contains("org.jose4j.lang.InvalidAlgorithmException"));
                    return; //Expected to get an exception and ignore the rest
                } else {
                    throw e;
                }
            }
            TestingHttpServerResponse response = request.getResponse();
            assertEquals(loginToKeycloak ? HttpStatus.SC_MOVED_TEMPORARILY : HttpStatus.SC_FORBIDDEN, response.getStatusCode());
            assertEquals(Status.NO_AUTH, request.getResult());
            if (expectedScope != null) {
                assertTrue(response.getFirstResponseHeaderValue("Location").contains("scope=" + expectedScope));
            }
            if (oidcClientConfiguration.getAuthenticationRequestFormat().contains(REQUEST_TYPE_REQUEST_URI)) {
                assertTrue(response.getFirstResponseHeaderValue("Location").contains("scope=" + OIDC_SCOPE));
                assertTrue(response.getFirstResponseHeaderValue("Location").contains("request_uri="));
            } else if (oidcClientConfiguration.getAuthenticationRequestFormat().contains(REQUEST_TYPE_REQUEST)) {
                assertTrue(response.getFirstResponseHeaderValue("Location").contains("scope=" + OIDC_SCOPE));
                assertTrue(response.getFirstResponseHeaderValue("Location").contains("request="));
            }

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

    private InputStream getOidcConfigurationInputStreamWithRequestParameter(String requestParameter, String signAlgorithm, String encryptAlgorithm, String encMethod){
        String oidcConfig = "{\n" +
                "    \"client-id\" : \"" + CLIENT_ID + "\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "/" + "\",\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"authentication-request-format\" : \"" + requestParameter + "\",\n" +
                "    \"request-object-signing-algorithm\" : \"" + signAlgorithm + "\",\n" +
                "    \"request-object-encryption-algorithm\" : \"" + encryptAlgorithm + "\",\n" +
                "    \"request-object-content-encryption-algorithm\" : \"" + encMethod + "\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithRequestParameter(String requestParameter, String signAlgorithm, String encryptAlgorithm, String encMethod, String keyStorePath, String alias, String keyStoreType){
        String oidcConfig = "{\n" +
                "    \"client-id\" : \"" + CLIENT_ID + "\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "/" + "\",\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"authentication-request-format\" : \"" + requestParameter + "\",\n" +
                "    \"request-object-signing-algorithm\" : \"" + signAlgorithm + "\",\n" +
                "    \"request-object-encryption-algorithm\" : \"" + encryptAlgorithm + "\",\n" +
                "    \"request-object-content-encryption-algorithm\" : \"" + encMethod + "\",\n" +
                "    \"client-keystore-file\" : \"" + keyStorePath + "\",\n" +
                "    \"client-keystore-type\" : \"" + keyStoreType + "\",\n" +
                "    \"client-keystore-password\" : \"" + KEYSTORE_PASS + "\",\n" +
                "    \"client-key-password\" : \"" + KEYSTORE_PASS + "\",\n" +
                "    \"client-key-alias\" : \"" + alias + "\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }
}

