/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2022 Red Hat, Inc., and individual contributors
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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
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
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.AfterClass;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.DockerClientFactory;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.auth.callback.SecurityIdentityCallback;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.credential.Credential;
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
public class OidcBaseTest extends AbstractBaseHttpTest {

    public static final String CLIENT_ID = "test-webapp";
    public static final String CLIENT_SECRET = "longerclientsecretthatisstleast256bitslong";
    public static KeycloakContainer KEYCLOAK_CONTAINER;
    public static final String TEST_REALM = "WildFly";
    public static final String TEST_REALM_WITH_SCOPES = "WildFlyScopes";
    public static final String TENANT1_REALM = "tenant1";
    public static final String TENANT2_REALM = "tenant2";
    public static final String KEYCLOAK_USERNAME = "username";
    public static final String KEYCLOAK_PASSWORD = "password";
    public static final String KEYCLOAK_LOGIN = "login";
    public static final int CLIENT_PORT = 5002;
    public static final String CLIENT_APP = "clientApp";
    public static final String CLIENT_PAGE_TEXT = "Welcome page!";
    public static final String CLIENT_HOST_NAME = "localhost";
    public static MockWebServer client; // to simulate the application being secured
    public static final Boolean CONFIGURE_CLIENT_SCOPES = true; // to simulate the application being secured
    public static final String TENANT1_ENDPOINT = "tenant1";
    public static final String TENANT2_ENDPOINT = "tenant2";
    protected HttpServerAuthenticationMechanismFactory oidcFactory;

    public enum RequestObjectErrorType {
        INVALID_ALGORITHM,
        MISSING_CLIENT_SECRET,
        INVALID_REQUEST_FORMAT,
        MISSING_ENC_VALUE
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

    protected static void sendRealmCreationRequest(RealmRepresentation realm) {
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

    protected static boolean isDockerAvailable() {
        try {
            DockerClientFactory.instance().client();
            return true;
        } catch (Throwable ex) {
            return false;
        }
    }
    protected CallbackHandler getCallbackHandler() {
       return getCallbackHandler(false, null, null);
    }

    protected CallbackHandler getCallbackHandler(String expectedPrincipal) {
        return getCallbackHandler(false, null, expectedPrincipal);
    }

    protected CallbackHandler getCallbackHandler(boolean checkScope, String expectedScopes) {
        return getCallbackHandler(checkScope, expectedScopes, null);
    }

    protected CallbackHandler getCallbackHandler(boolean checkScope, String expectedScopes, String expectedPrincipal) {
        return callbacks -> {
            for(Callback callback : callbacks) {
                if (callback instanceof EvidenceVerifyCallback) {
                    Evidence evidence = ((EvidenceVerifyCallback) callback).getEvidence();
                    ((EvidenceVerifyCallback) callback).setVerified(evidence.getDecodedPrincipal() != null);
                    if (expectedPrincipal != null) {
                        assertEquals(expectedPrincipal, evidence.getDecodedPrincipal().getName());
                    }
                } else if (callback instanceof AuthenticationCompleteCallback) {
                    // NO-OP
                } else if (callback instanceof IdentityCredentialCallback) {
                    if (checkScope) {
                        try {
                            checkForScopeClaims(callback, expectedScopes);
                        } catch (InvalidJwtException e) {
                            throw new RuntimeException(e);
                        }
                    }
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

    protected static Dispatcher createAppResponse(HttpServerAuthenticationMechanism mechanism, int expectedStatusCode, String expectedLocation, String clientPageText) {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest recordedRequest) throws InterruptedException {
                String path = recordedRequest.getPath();
                if (path.contains("/" + CLIENT_APP) && path.contains("&code=")) {
                    try {
                        TestingHttpServerRequest request = new TestingHttpServerRequest(new String[0],
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

    protected static Dispatcher createAppResponse(HttpServerAuthenticationMechanism mechanism, int expectedStatusCode, String expectedLocation, String clientPageText,
                                                  Map<String, Object> attachments) {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest recordedRequest) throws InterruptedException {
                String path = recordedRequest.getPath();
                if (path.contains("/" + CLIENT_APP) && path.contains("&code=")) {
                    try {
                        TestingHttpServerRequest request = new TestingHttpServerRequest(new String[0],
                                new URI(recordedRequest.getRequestUrl().toString()), recordedRequest.getHeader("Cookie"));
                        mechanism.evaluateRequest(request);
                        TestingHttpServerResponse response = request.getResponse();
                        assertEquals(expectedStatusCode, response.getStatusCode());
                        assertEquals(expectedLocation, response.getLocation());
                        for (String key : request.getAttachments().keySet()) {
                            attachments.put(key, request.getAttachments().get(key));
                        }
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

    protected static Dispatcher createAppResponse(HttpServerAuthenticationMechanism mechanism, String clientPageText,
                                                  Map<String, Object> attachments, String tenant, boolean sameTenant) {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest recordedRequest) throws InterruptedException {
                String path = recordedRequest.getPath();
                if (path.contains("/" + CLIENT_APP + "/" + tenant)) {
                    try {
                        TestingHttpServerRequest request = new TestingHttpServerRequest(new String[0],
                                new URI(recordedRequest.getRequestUrl().toString()), attachments);
                        mechanism.evaluateRequest(request);
                        TestingHttpServerResponse response = request.getResponse();
                        if (sameTenant) {
                            // should be able to access the same tenant without logging in again
                            assertEquals(Status.COMPLETE, request.getResult());
                            return new MockResponse().setBody(clientPageText);
                        } else {
                            // should be redirected to Keycloak to access the other tenant
                            assertEquals(Status.NO_AUTH, request.getResult());
                            assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, response.getStatusCode());
                            assertTrue(response.getLocation().contains(KEYCLOAK_CONTAINER.getAuthServerUrl()));
                            HtmlPage keycloakLoginPage = getWebClient().getPage(response.getLocation());
                            HtmlForm loginForm = keycloakLoginPage.getForms().get(0);
                            assertNotNull(loginForm.getInputByName(KEYCLOAK_USERNAME));
                            assertNotNull(loginForm.getInputByName(KEYCLOAK_PASSWORD));
                        }
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
                return new MockResponse()
                        .setBody("");
            }
        };
    }

    static WebClient getWebClient() {
        WebClient webClient = new WebClient();
        webClient.setCssErrorHandler(new SilentCssErrorHandler());
        webClient.setJavaScriptErrorListener(new SilentJavaScriptErrorListener());
        return webClient;
    }

    protected static String getClientUrl() {
        return "http://" + CLIENT_HOST_NAME + ":" + CLIENT_PORT + "/" + CLIENT_APP;
    }

    protected static String getClientUrlForTenant(String tenant) {
        return "http://" + CLIENT_HOST_NAME + ":" + CLIENT_PORT + "/" + CLIENT_APP + "/" + tenant;
    }

    protected HtmlInput loginToKeycloak(String username, String password, URI requestUri, String location, List<HttpServerCookie> cookies) throws IOException {
        return loginToKeycloak(getWebClient(), username, password, requestUri, location, cookies);
    }

    protected HtmlInput loginToKeycloak(WebClient webClient, String username, String password, URI requestUri, String location, List<HttpServerCookie> cookies) throws IOException {
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

    protected String getCookieString(HttpServerCookie cookie) {
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

    protected void checkForScopeClaims(Callback callback, String expectedScopes) throws InvalidJwtException {
        Credential credential = ((IdentityCredentialCallback)callback).getCredential();
        String token = ((BearerTokenCredential) credential).getToken();
        JwtClaims jwtClaims = new JwtConsumerBuilder().setSkipSignatureVerification().setSkipAllValidators().build().processToClaims(token);

        if (expectedScopes != null) {
            if (expectedScopes.contains("email")) {
                assertTrue(jwtClaims.getClaimValueAsString("email_verified").contains(String.valueOf(KeycloakConfiguration.EMAIL_VERIFIED)));
            }
            if (expectedScopes.contains("profile")) {
                assertTrue(jwtClaims.getClaimValueAsString("preferred_username").contains(KeycloakConfiguration.ALICE));
            }
        }
    }

    // Note: The tests will fail if `localhost` is not listed first in `/etc/hosts` file for the loopback addresses (IPv4 and IPv6).
    protected void performAuthentication(InputStream oidcConfig, String username, String password, boolean loginToKeycloak,
                                       int expectedDispatcherStatusCode, String expectedLocation, String clientPageText) throws Exception {
        performAuthentication(oidcConfig, username, password, loginToKeycloak, expectedDispatcherStatusCode, getClientUrl(), expectedLocation,
                clientPageText, null, false);
    }

    protected void performAuthentication(InputStream oidcConfig, String username, String password, boolean loginToKeycloak,
                                         int expectedDispatcherStatusCode, String clientUrl, String expectedLocation, String clientPageText) throws Exception {
        performAuthentication(oidcConfig, username, password, loginToKeycloak, expectedDispatcherStatusCode, clientUrl, expectedLocation,
                clientPageText, null, false);
    }

    protected void performAuthentication(InputStream oidcConfig, String username, String password, boolean loginToKeycloak, int expectedDispatcherStatusCode,
                                         String expectedLocation, String clientPageText, String expectedScope, boolean checkInvalidScopeError) throws Exception {
        performAuthentication(oidcConfig, username, password, loginToKeycloak, expectedDispatcherStatusCode, getClientUrl(), expectedLocation, clientPageText,
                expectedScope, checkInvalidScopeError);
    }

    private void performAuthentication(InputStream oidcConfig, String username, String password, boolean loginToKeycloak,
                                       int expectedDispatcherStatusCode, String clientUrl, String expectedLocation, String clientPageText,
                                       String expectedScope, boolean checkInvalidScopeError) throws Exception {
        try {
            Map<String, Object> props = new HashMap<>();
            OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(oidcConfig);
            assertEquals(OidcClientConfiguration.RelativeUrlsUsed.NEVER, oidcClientConfiguration.getRelativeUrls());

            OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
            oidcFactory = new OidcMechanismFactory(oidcClientContext);
            HttpServerAuthenticationMechanism mechanism;
            if (expectedScope == null) {
                mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler());
            } else {
                mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler(true, expectedScope));
            }

            URI requestUri = new URI(clientUrl);
            TestingHttpServerRequest request = new TestingHttpServerRequest(null, requestUri);
            mechanism.evaluateRequest(request);
            TestingHttpServerResponse response = request.getResponse();
            assertEquals(loginToKeycloak ? HttpStatus.SC_MOVED_TEMPORARILY : HttpStatus.SC_FORBIDDEN, response.getStatusCode());
            assertEquals(Status.NO_AUTH, request.getResult());
            if (expectedScope != null) {
                assertTrue(response.getFirstResponseHeaderValue("Location").contains("scope=" + expectedScope));
            }

            if (loginToKeycloak) {
                client.setDispatcher(createAppResponse(mechanism, expectedDispatcherStatusCode, expectedLocation, clientPageText));

                if (checkInvalidScopeError) {
                    WebClient webClient = getWebClient();
                    TextPage keycloakLoginPage = webClient.getPage(response.getLocation());
                    assertTrue(keycloakLoginPage.getWebResponse().getWebRequest().toString().contains("error_description=Invalid+scopes"));
                } else {
                    TextPage page = loginToKeycloak(username, password, requestUri, response.getLocation(),
                            response.getCookies()).click();
                    assertTrue(page.getContent().contains(clientPageText));
                }
            }
        } finally {
            client.setDispatcher(new QueueDispatcher());
        }
    }

    protected InputStream getOidcConfigurationInputStreamWithProviderUrl() {
        String oidcConfig = "{\n" +
                "    \"" + Oidc.RESOURCE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + Oidc.PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + Oidc.PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"" + Oidc.SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + Oidc.CREDENTIALS + "\" : {\n" +
                "        \"" + Oidc.ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }
}
