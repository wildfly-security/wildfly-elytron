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
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.apache.http.HttpStatus;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.DockerClientFactory;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.auth.callback.SecurityIdentityCallback;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.impl.AbstractBaseHttpTest;
import org.wildfly.security.jose.util.JsonSerialization;

import com.gargoylesoftware.htmlunit.SilentCssErrorHandler;
import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.javascript.SilentJavaScriptErrorListener;

import io.restassured.RestAssured;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.QueueDispatcher;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * Tests for the OpenID Connect authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class OidcTest extends AbstractBaseHttpTest {

    public static final String CLIENT_ID = "test-webapp";
    public static final String CLIENT_SECRET = "secret";
    private static KeycloakContainer KEYCLOAK_CONTAINER;
    private static final String TEST_REALM = "WildFly";
    private static final String KEYCLOAK_USERNAME = "username";
    private static final String KEYCLOAK_PASSWORD = "password";
    private static final String KEYCLOAK_LOGIN = "login";
    private static final int CLIENT_PORT = 5002;
    private static final String CLIENT_APP = "clientApp";
    private static final String CLIENT_PAGE_TEXT = "Welcome page!";
    private static final String CLIENT_HOST_NAME = "localhost";
    private static MockWebServer client; // to simulate the application being secured

    protected HttpServerAuthenticationMechanismFactory oidcFactory;

    @BeforeClass
    public static void startTestContainers() throws Exception {
        assumeTrue("Docker isn't available, OIDC tests will be skipped", isDockerAvailable());
        KEYCLOAK_CONTAINER = new KeycloakContainer();
        KEYCLOAK_CONTAINER.start();
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TEST_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP));
        client = new MockWebServer();
        client.start(CLIENT_PORT);
    }

    private static Dispatcher createAppResponse(HttpServerAuthenticationMechanism mechanism, int expectedStatusCode, String expectedLocation, String clientPageText) {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest recordedRequest) throws InterruptedException {
                String path = recordedRequest.getPath();
                if (path.contains("/" + CLIENT_APP) && path.contains("&code=")) {
                    try {
                        TestingHttpServerRequest request = new TestingHttpServerRequest(null,
                                new URI(recordedRequest.getRequestUrl().toString()), recordedRequest.getHeader("Cookie"));
                        mechanism.evaluateRequest(request);
                        TestingHttpServerResponse response = request.getResponse();
                        assertEquals(expectedStatusCode, response.getStatusCode());
                        assertEquals(expectedLocation, response.getLocation());
                        return new MockResponse().setBody(clientPageText);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
                return new MockResponse()
                        .setBody("");
            }
        };
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

    private static void sendRealmCreationRequest(RealmRepresentation realm) {
        try {
            RestAssured
                    .given()
                    .auth().oauth2(KeycloakConfiguration.getAdminAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl()))
                    .contentType("application/json")
                    .body(JsonSerialization.writeValueAsBytes(realm))
                    .when()
                    .post(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/admin/realms").then()
                    .statusCode(201);
        } catch (IOException e) {
            throw new RuntimeException(e);
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
    public void testTokenSignatureAlgorithm() throws Exception {
        // keycloak uses RS256
        performAuthentication(getOidcConfigurationInputStreamWithTokenSignatureAlgorithm(), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT);
    }

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

    private WebClient getWebClient() {
        WebClient webClient = new WebClient();
        webClient.setCssErrorHandler(new SilentCssErrorHandler());
        webClient.setJavaScriptErrorListener(new SilentJavaScriptErrorListener());
        return webClient;
    }

    private HtmlInput loginToKeycloak(String username, String password, URI requestUri, String location, List<HttpServerCookie> cookies) throws IOException {
        WebClient webClient = getWebClient();
        if (cookies != null) {
            for (HttpServerCookie cookie : cookies) {
                webClient.addCookie(getCookieString(cookie), requestUri.toURL(), null);
            }
        }
        HtmlPage keycloakLoginPage = webClient.getPage(location);
        HtmlForm loginForm = keycloakLoginPage.getForms().get(0);
        loginForm.getInputByName(KEYCLOAK_USERNAME).setValueAttribute(username);
        loginForm.getInputByName(KEYCLOAK_PASSWORD).setValueAttribute(password);
        return loginForm.getInputByName(KEYCLOAK_LOGIN);
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

    private CallbackHandler getCallbackHandler() {
        return callbacks -> {
            for(Callback callback : callbacks) {
                if (callback instanceof EvidenceVerifyCallback) {
                    Evidence evidence = ((EvidenceVerifyCallback) callback).getEvidence();
                    ((EvidenceVerifyCallback) callback).setVerified(evidence.getDecodedPrincipal() != null);
                } else if (callback instanceof AuthenticationCompleteCallback) {
                    // NO-OP
                } else if (callback instanceof IdentityCredentialCallback) {
                    // NO-OP
                } else if (callback instanceof AuthorizeCallback) {
                    ((AuthorizeCallback) callback).setAuthorized(true);
                } else if (callback instanceof SecurityIdentityCallback) {
                    ((SecurityIdentityCallback) callback).setSecurityIdentity(SecurityDomain.builder().build().getCurrentSecurityIdentity());
                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        };
    }

    private static boolean isDockerAvailable() {
        try {
            DockerClientFactory.instance().client();
            return true;
        } catch (Throwable ex) {
            return false;
        }
    }

    private String getCookieString(HttpServerCookie cookie) {
        final StringBuilder header = new StringBuilder(cookie.getName());
        header.append("=");
        if(cookie.getValue() != null) {
            header.append(cookie.getValue());
        }
        if (cookie.getPath() != null) {
            header.append("; Path=");
            header.append(cookie.getPath());
        }
        if (cookie.getDomain() != null) {
            header.append("; Domain=");
            header.append(cookie.getDomain());
        }
        if (cookie.isSecure()) {
            header.append("; Secure");
        }
        if (cookie.isHttpOnly()) {
            header.append("; HttpOnly");
        }
        if (cookie.getMaxAge() >= 0) {
            header.append("; Max-Age=");
            header.append(cookie.getMaxAge());
        }
        return header.toString();
    }

    private static String getClientUrl() {
        return "http://" + CLIENT_HOST_NAME + ":" + CLIENT_PORT + "/" + CLIENT_APP;
    }
}