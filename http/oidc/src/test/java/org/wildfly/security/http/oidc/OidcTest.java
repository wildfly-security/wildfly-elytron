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

import static org.jose4j.jws.AlgorithmIdentifiers.NONE;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_USING_SHA256;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_USING_SHA512;
import static org.jose4j.jws.AlgorithmIdentifiers.HMAC_SHA256;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_PSS_USING_SHA256;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.KEYSTORE_CLASSPATH;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.KEYSTORE_PASS;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.PKCS12_KEYSTORE_TYPE;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.RSA1_5;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.RSA_OAEP;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.RSA_OAEP_256;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.A128CBC_HS256;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.A192CBC_HS384;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.A256CBC_HS512;
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
import static org.wildfly.security.http.oidc.Oidc.AUTH_SERVER_URL;
import static org.wildfly.security.http.oidc.Oidc.AUTHENTICATION_REQUEST_FORMAT;
import static org.wildfly.security.http.oidc.Oidc.CREDENTIALS;
import static org.wildfly.security.http.oidc.Oidc.ClientCredentialsProviderType;
import static org.wildfly.security.http.oidc.Oidc.PROVIDER_URL;
import static org.wildfly.security.http.oidc.Oidc.OIDC_NAME;
import static org.wildfly.security.http.oidc.Oidc.OIDC_SCOPE;
import static org.wildfly.security.http.oidc.Oidc.PUBLIC_CLIENT;
import static org.wildfly.security.http.oidc.Oidc.PRINCIPAL_ATTRIBUTE;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_SIGNING_ALGORITHM;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_SIGNING_KEYSTORE_FILE;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_SIGNING_KEYSTORE_PASSWORD;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_SIGNING_KEYSTORE_TYPE;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_SIGNING_KEY_PASSWORD;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_SIGNING_KEY_ALIAS;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_ENCRYPTION_ALG_VALUE;
import static org.wildfly.security.http.oidc.Oidc.REQUEST_OBJECT_ENCRYPTION_ENC_VALUE;
import static org.wildfly.security.http.oidc.Oidc.RESOURCE;
import static org.wildfly.security.http.oidc.Oidc.REALM;
import static org.wildfly.security.http.oidc.Oidc.SCOPE;
import static org.wildfly.security.http.oidc.Oidc.SSL_REQUIRED;
import static org.wildfly.security.http.oidc.Oidc.TOKEN_SIGNATURE_ALGORITHM;
import static org.wildfly.security.http.oidc.Oidc.AuthenticationRequestFormat.OAUTH2;
import static org.wildfly.security.http.oidc.Oidc.AuthenticationRequestFormat.REQUEST;
import static org.wildfly.security.http.oidc.Oidc.AuthenticationRequestFormat.REQUEST_URI;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.WebClient;
import io.restassured.RestAssured;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.QueueDispatcher;
import org.apache.http.HttpStatus;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;

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
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TEST_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP, false));
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TEST_REALM_WITH_SCOPES, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP, CONFIGURE_CLIENT_SCOPES));
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TENANT1_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP, ACCESS_TOKEN_LIFESPAN, SESSION_MAX_LIFESPAN, false, true));
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TENANT2_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP, ACCESS_TOKEN_LIFESPAN, SESSION_MAX_LIFESPAN, false, true));
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
                    .delete(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/admin/realms/" + TEST_REALM_WITH_SCOPES).then().statusCode(204);
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
    public void testTimeoutConfigurationOptions() throws Exception {
        OidcClientConfigurationBuilder.build(getOidcConfigurationInputStreamWithTimeoutOptions(5000, 5000, 5000));
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
    public void testInvalidScope() throws Exception {
        String expectedScope = OIDC_SCOPE + "+INVALID_SCOPE";
        performAuthentication(getOidcConfigurationInputStreamWithScope("INVALID_SCOPE"), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), "error=invalid_scope", expectedScope, true);
    }

    @Test
    public void testEmptyScope() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithScope(""), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT, OIDC_SCOPE, false);
    }

    @Test
    public void testSingleScopeValue() throws Exception {
        String expectedScope = OIDC_SCOPE + "+profile";
        performAuthentication(getOidcConfigurationInputStreamWithScope("profile"), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT, expectedScope, false);
    }

    @Test
    public void testMultipleScopeValue() throws Exception {
        String expectedScope = OIDC_SCOPE + "+phone+profile+email";
        performAuthentication(getOidcConfigurationInputStreamWithScope("email phone profile"), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT, expectedScope, false);
    }

    @Test
    public void testOpenIDScopeValue() throws Exception {
        String expectedScope = OIDC_SCOPE;
        performAuthentication(getOidcConfigurationInputStreamWithScope(OIDC_SCOPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT, expectedScope, false);
    }

    @Test
    public void testOpenIDWithMultipleScopeValue() throws Exception {
        String expectedScope = OIDC_SCOPE + "+phone+profile+email";//order gets changed when combining with query parameters
        performAuthentication(getOidcConfigurationInputStreamWithScope("email phone profile " + OIDC_SCOPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT, expectedScope, false);
    }

    // Note: The tests will fail if `localhost` is not listed first in `/etc/hosts` file for the loopback addresses (IPv4 and IPv6).
    @Test
    public void testSuccessfulOauth2Request() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(OAUTH2.getValue(), "", "", ""), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSuccessfulPlaintextRequest() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST.getValue(), NONE, "", ""), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSuccessfulPlaintextEncryptedRequest() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST.getValue(), NONE, RSA_OAEP, A128CBC_HS256), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSuccessfulRsaSignedAndEncryptedRequest() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST.getValue(), RSA_USING_SHA512, RSA_OAEP, A192CBC_HS384, KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, PKCS12_KEYSTORE_TYPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSuccessfulPsSignedAndRsaEncryptedRequest() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST.getValue(), RSA_PSS_USING_SHA256, RSA_OAEP_256, A256CBC_HS512, KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, PKCS12_KEYSTORE_TYPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testInvalidSigningAlgorithm() throws Exception {
        //ES256K is a valid signature algorithm, but not one of the ones supported by keycloak
        testRequestObjectInvalidConfiguration(getOidcConfigurationInputStreamWithRequestParameter(REQUEST.getValue(), "ES256K", RSA_OAEP_256, A256CBC_HS512, KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, PKCS12_KEYSTORE_TYPE), RequestObjectErrorType.INVALID_ALGORITHM);
    }

    @Test
    public void testSuccessfulRsaSignedRequest() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST.getValue(), RSA_USING_SHA256, "", "", KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, PKCS12_KEYSTORE_TYPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSuccessfulPsSignedRequest() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST.getValue(), RSA_PSS_USING_SHA256, "", "", KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, PKCS12_KEYSTORE_TYPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }
    @Test
    public void testInvalidRequestEncryptionAlgorithm() throws Exception {
        // None is not a valid algorithm for encrypting jwt's and RSA-OAEP is not a valid algorithm for signing
        testRequestObjectInvalidConfiguration(getOidcConfigurationInputStreamWithRequestParameter(REQUEST.getValue(), RSA1_5, NONE, NONE, KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, PKCS12_KEYSTORE_TYPE), RequestObjectErrorType.INVALID_ALGORITHM);
    }

    @Test
    public void testSuccessfulPlaintextRequestUri() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_URI.getValue(), NONE, "", ""), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSuccessfulHmacSignedRequestUri() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST.getValue(), HMAC_SHA256, "", ""), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSuccessfulHmacSignedAndEncryptedRequestUri() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST.getValue(), HMAC_SHA256, RSA_OAEP, A128CBC_HS256), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSuccessfulSignedAndEncryptedRequestUri() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_URI.getValue(), RSA_USING_SHA256, RSA_OAEP_256, A256CBC_HS512, KEYSTORE_CLASSPATH + KeycloakConfiguration.RSA_KEYSTORE_FILE_NAME, KeycloakConfiguration.KEYSTORE_ALIAS, PKCS12_KEYSTORE_TYPE), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSuccessfulHmacSignedRequestObjectWithoutSecret() throws Exception {
        // this is supposed to fail since for symmetric algorithms we sign the request object with the client secret
        testRequestObjectInvalidConfiguration(getOidcConfigurationInputStreamWithRequestObjectPublicClient(REQUEST.getValue(), HMAC_SHA256), RequestObjectErrorType.MISSING_CLIENT_SECRET);
    }

    @Test
    public void testIncorrectAuthenticationFormat() throws Exception {
        testRequestObjectInvalidConfiguration(getOidcConfigurationInputStreamWithRequestObjectPublicClient("INVALID_REQUEST_PARAMETER", HMAC_SHA256), RequestObjectErrorType.INVALID_REQUEST_FORMAT);
    }

    @Test
    public void testRequestObjectConfigMissingENCValue() throws Exception {
        testRequestObjectInvalidConfiguration(getOidcConfigurationInputStreamWithoutEncValue(REQUEST.getValue(), RSA_OAEP), RequestObjectErrorType.MISSING_ENC_VALUE);
    }

    @Test
    // Generate an invalid sessionRandomValue so that the nonce check fails
    public void testRequestParameterNonceMismatch() throws Exception {
        performAuthentication(
                getOidcConfigurationInputStreamWithRequestParameter(REQUEST.getValue(), NONE, "", ""),
                KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,true,
                HttpStatus.SC_FORBIDDEN,null, CLIENT_PAGE_TEXT, true);
    }

    @Test
    public void testRequestUriParameterNonceMismatch() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_URI.getValue(), NONE, "", ""),
                KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD, true,
                HttpStatus.SC_FORBIDDEN, null, CLIENT_PAGE_TEXT, true);
    }

    @Test
    public void testStandardConfigWithNonceMismatch() throws Exception {
        performAuthentication(getOidcConfigurationInputStreamWithProviderUrl(), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_FORBIDDEN, null, CLIENT_PAGE_TEXT, true);
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

    /**
     *  Check that a RefreshableOidcSecurityContext.tokenRefresh works now that
     *  a request nonce has been added to elytron.
     */
    @Test
    public void testRefreshToken() throws Exception {
        Map<String, Object> props = new HashMap<>();
        OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(getOidcRefreshConfigurationInputStream());
        OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
        oidcFactory = new OidcMechanismFactory(oidcClientContext);
        HttpServerAuthenticationMechanism mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler());

        URI requestUri = new URI(getClientUrl());
        TestingHttpServerRequest request = new TestingHttpServerRequest(null, requestUri);
        mechanism.evaluateRequest(request);
        TestingHttpServerResponse response = request.getResponse();
        assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, response.getStatusCode());
        assertEquals(Status.NO_AUTH, request.getResult());

        client.setDispatcher(createAppResponse(mechanism, HttpStatus.SC_MOVED_TEMPORARILY,
                getClientUrl(), CLIENT_PAGE_TEXT, true));

        TextPage page = loginToKeycloak(KeycloakConfiguration.ALICE,
                KeycloakConfiguration.ALICE_PASSWORD, requestUri, response.getLocation(),
                response.getCookies()).click();
        assertTrue(page.getContent().contains(CLIENT_PAGE_TEXT));
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
                                        int expectedDispatcherStatusCode, String expectedLocation, String clientPageText,
                                        CallbackHandler callbackHandler) throws Exception {
        try {
            Map<String, Object> props = new HashMap<>();
            OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(oidcConfig);
            assertEquals(OidcClientConfiguration.RelativeUrlsUsed.NEVER, oidcClientConfiguration.getRelativeUrls());

            OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
            oidcFactory = new OidcMechanismFactory(oidcClientContext);

            HttpServerAuthenticationMechanism mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, callbackHandler);

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

    private void testRequestObjectInvalidConfiguration(InputStream oidcConfig, RequestObjectErrorType requestObjectErrorType) throws Exception {
        try {
            Map<String, Object> props = new HashMap<>();
            try {
                OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(oidcConfig);
                if (requestObjectErrorType == RequestObjectErrorType.MISSING_ENC_VALUE || requestObjectErrorType == RequestObjectErrorType.INVALID_REQUEST_FORMAT) {
                    Assert.fail("No error was thrown while attempting to build the client configuration.");
                }
                assertEquals(OidcClientConfiguration.RelativeUrlsUsed.NEVER, oidcClientConfiguration.getRelativeUrls());

                OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
                oidcFactory = new OidcMechanismFactory(oidcClientContext);
                HttpServerAuthenticationMechanism mechanism;

                if (oidcClientConfiguration.getAuthenticationRequestFormat().contains(REQUEST.getValue())) {
                    mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler(true, "+phone+profile+email"));
                } else {
                    mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler());
                }

                URI requestUri = new URI(getClientUrl());
                TestingHttpServerRequest request = new TestingHttpServerRequest(null, requestUri);
                try {
                    mechanism.evaluateRequest(request);
                    Assert.fail("No error was thrown while attempting to evaluate the request");
                } catch (Exception e) {

                    if (requestObjectErrorType == RequestObjectErrorType.INVALID_ALGORITHM) {
                        assertTrue(e.getMessage().contains("Failed to create the authentication request"));
                    } else if (requestObjectErrorType == RequestObjectErrorType.MISSING_CLIENT_SECRET) {
                        assertTrue(e.getMessage().contains("The client secret has not been configured."));
                    } else {
                        throw e;
                    }
                }
            } catch (Exception e) {
                if (requestObjectErrorType == RequestObjectErrorType.INVALID_REQUEST_FORMAT) {
                    assertTrue(e.getMessage().contains("Authentication request format must be one of the following: oauth2, request, request_uri."));
                } else if (requestObjectErrorType == RequestObjectErrorType.MISSING_ENC_VALUE) {
                    assertTrue(e.getMessage().contains("Both request object encryption algorithm and request object content encryption algorithm must be configured to encrypt the request object."));
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
                "    \"" + REALM + "\" : \"" + TEST_REALM + "\",\n" +
                "    \"" + RESOURCE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + AUTH_SERVER_URL + "\" : \"" + authServerUrl + "\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + clientSecret + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithTimeoutOptions(int connectionTimeoutMillis, int connectionTtlMillis, int socketTimeoutMillis) {
        String oidcConfig = "{\n" +
                "    \"realm\" : \"" + TEST_REALM + "\",\n" +
                "    \"resource\" : \"" + CLIENT_ID + "\",\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"connection-timeout-millis\" : \"" + connectionTimeoutMillis + "\",\n" +
                "    \"connection-ttl-millis\" : \"" + connectionTtlMillis + "\",\n" +
                "    \"socket-timeout-millis\" : \"" + socketTimeoutMillis + "\",\n" +
                "    \"auth-server-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithEnvironmentVariableExpression() {
        String oidcConfig = "{\n" +
                "    \"" + RESOURCE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "${oidc.provider-url-env}\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithSystemPropertyExpression() {
        String oidcConfig = "{\n" +
                "    \"" + RESOURCE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + PROVIDER_URL + "\" : \"${oidc.provider.url}\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithProviderUrlTrailingSlash() {
        String oidcConfig = "{\n" +
                "    \"" + RESOURCE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "/" + "\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationMissingRequiredOption() {
        String oidcConfig = "{\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithTokenSignatureAlgorithm() {
        String oidcConfig = "{\n" +
                "    \"" + TOKEN_SIGNATURE_ALGORITHM + "\" : \"RS256\",\n" +
                "    \"" + RESOURCE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }
    private InputStream getOidcConfigurationInputStreamWithScope(String scopeValue){
        String oidcConfig = "{\n" +
                "    \"" + Oidc.CLIENT_ID_JSON_VALUE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM_WITH_SCOPES + "/" + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + SCOPE + "\" : \"" + scopeValue + "\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }
    private InputStream getOidcConfigurationInputStreamWithRequestParameter(String requestParameter, String signingAlgorithm, String encryptionAlgorithm, String encMethod){
        String oidcConfig = "{\n" +
                "    \"" + Oidc.CLIENT_ID_JSON_VALUE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM_WITH_SCOPES + "/" + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + AUTHENTICATION_REQUEST_FORMAT + "\" : \"" + requestParameter + "\",\n" +
                "    \"" + REQUEST_OBJECT_SIGNING_ALGORITHM + "\" : \"" + signingAlgorithm + "\",\n" +
                "    \"" + REQUEST_OBJECT_ENCRYPTION_ALG_VALUE + "\" : \"" + encryptionAlgorithm + "\",\n" +
                "    \"" + REQUEST_OBJECT_ENCRYPTION_ENC_VALUE + "\" : \"" + encMethod + "\",\n" +
                "    \"" + SCOPE + "\" : \"profile email phone\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithoutEncValue(String requestParameter, String encryptionAlgorithm){
        String oidcConfig = "{\n" +
                "    \"" + Oidc.CLIENT_ID_JSON_VALUE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM_WITH_SCOPES + "/" + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + AUTHENTICATION_REQUEST_FORMAT + "\" : \"" + requestParameter + "\",\n" +
                "    \"" + REQUEST_OBJECT_ENCRYPTION_ALG_VALUE + "\" : \"" + encryptionAlgorithm + "\",\n" +
                "    \"" + SCOPE + "\" : \"profile email phone\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithRequestParameter(String requestParameter, String signingAlgorithm, String encryptionAlgorithm, String encMethod, String keyStorePath, String alias, String keyStoreType){
        String oidcConfig = "{\n" +
                "    \"" + Oidc.CLIENT_ID_JSON_VALUE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM_WITH_SCOPES + "/" + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + AUTHENTICATION_REQUEST_FORMAT + "\" : \"" + requestParameter + "\",\n" +
                "    \"" + REQUEST_OBJECT_SIGNING_ALGORITHM + "\" : \"" + signingAlgorithm + "\",\n" +
                "    \"" + REQUEST_OBJECT_ENCRYPTION_ALG_VALUE + "\" : \"" + encryptionAlgorithm + "\",\n" +
                "    \"" + REQUEST_OBJECT_ENCRYPTION_ENC_VALUE + "\" : \"" + encMethod + "\",\n" +
                "    \"" + REQUEST_OBJECT_SIGNING_KEYSTORE_FILE + "\" : \"" + keyStorePath + "\",\n" +
                "    \"" + REQUEST_OBJECT_SIGNING_KEYSTORE_TYPE + "\" : \"" + keyStoreType + "\",\n" +
                "    \"" + REQUEST_OBJECT_SIGNING_KEYSTORE_PASSWORD + "\" : \"" + KEYSTORE_PASS + "\",\n" +
                "    \"" + REQUEST_OBJECT_SIGNING_KEY_PASSWORD + "\" : \"" + KEYSTORE_PASS + "\",\n" +
                "    \"" + REQUEST_OBJECT_SIGNING_KEY_ALIAS + "\" : \"" + alias + "\",\n" +
                "    \"" + SCOPE + "\" : \"email phone profile\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithRequestObjectPublicClient(String requestParameter, String signingAlgorithm){
        String oidcConfig = "{\n" +
                "    \"" + Oidc.CLIENT_ID_JSON_VALUE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM_WITH_SCOPES + "/" + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"true\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + AUTHENTICATION_REQUEST_FORMAT + "\" : \"" + requestParameter + "\",\n" +
                "    \"" + REQUEST_OBJECT_SIGNING_ALGORITHM + "\" : \"" + signingAlgorithm + "\",\n" +
                "    \"" + SCOPE + "\" : \"email phone profile\"\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithPrincipalAttribute(String principalAttributeValue) {
        String oidcConfig = "{\n" +
                "    \"" + PRINCIPAL_ATTRIBUTE + "\" : \"" + principalAttributeValue + "\",\n" +
                "    \"" + RESOURCE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    static InputStream getTenantConfigWithAuthServerUrl(String tenant) {
        String oidcConfig = "{\n" +
                "    \"" + REALM + "\" : \"" + tenant + "\",\n" +
                "    \""+ RESOURCE +"\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PUBLIC_CLIENT +"\" : \"false\",\n" +
                "    \"" + AUTH_SERVER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    static InputStream getTenantConfigWithProviderUrl(String tenant) {
        String oidcConfig = "{\n" +
                "    \"" + PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + tenant + "\",\n" +
                "    \"" + Oidc.CLIENT_ID_JSON_VALUE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private static final String getClientPageTestForTenant(String tenant) {
        return tenant.equals(TENANT1_ENDPOINT) ? TENANT1_ENDPOINT : TENANT2_ENDPOINT + ":" + CLIENT_PAGE_TEXT;
    }

    private InputStream getOidcRefreshConfigurationInputStream() {
        return getOidcRefreshConfigurationInputStream(CLIENT_SECRET, KEYCLOAK_CONTAINER.getAuthServerUrl());
    }
    private InputStream getOidcRefreshConfigurationInputStream(String clientSecret, String authServerUrl) {
        String oidcConfig = "{\n" +
                "    \"" + Oidc.CLIENT_ID_JSON_VALUE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + clientSecret + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }
}

