/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.http.oidc;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assume.assumeTrue;
import static org.wildfly.security.http.oidc.Oidc.OIDC_NAME;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import io.restassured.RestAssured;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.Scope;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public abstract class AbstractLogoutTest extends OidcBaseTest {

    private ElytronDispatcher dispatcher;
    private OidcClientConfiguration clientConfig;

    @BeforeClass
    public static void onBeforeClass() {
        assumeTrue("Docker isn't available, OIDC tests will be skipped", isDockerAvailable());
        KEYCLOAK_CONTAINER = new KeycloakContainer();
        KEYCLOAK_CONTAINER.start();
        System.setProperty("oidc.provider.url", KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM);
    }

    @AfterClass
    public static void onAfterClass() {
        System.clearProperty("oidc.provider.url");
    }

    @AfterClass
    public static void generalCleanup() {
        // no-op
    }

    @Before
    public void onBefore() throws Exception {
        OidcBaseTest.client = new MockWebServer();
        OidcBaseTest.client.start(new InetSocketAddress(0).getAddress(), CLIENT_PORT);
        configureDispatcher();
        RealmRepresentation realm = KeycloakConfiguration.getRealmRepresentation(TEST_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP, false);

        realm.setAccessTokenLifespan(100);
        realm.setSsoSessionMaxLifespan(100);

        ClientRepresentation client = realm.getClients().get(0);

        client.setAttributes(new HashMap<>());

        doConfigureClient(client);

        List<String> redirectUris = new ArrayList<>(client.getRedirectUris());

        redirectUris.add("*");

        client.setRedirectUris(redirectUris);

        sendRealmCreationRequest(realm);
    }

    @After
    public void onAfter() throws IOException {
        client.shutdown();
        RestAssured
                .given()
                .auth().oauth2(KeycloakConfiguration.getAdminAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl()))
                .when()
                .delete(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/admin/realms/" + TEST_REALM).then().statusCode(204);
    }

    protected void doConfigureClient(ClientRepresentation client) {
    }

    protected OidcJsonConfiguration getClientConfiguration() {
        OidcJsonConfiguration config = new OidcJsonConfiguration();

        config.setRealm(TEST_REALM);
        config.setResource(CLIENT_ID);
        config.setPublicClient(false);
        config.setAuthServerUrl(KEYCLOAK_CONTAINER.getAuthServerUrl());
        config.setSslRequired("EXTERNAL");
        config.setCredentials(new HashMap<>());
        config.getCredentials().put("secret", CLIENT_SECRET);

        return config;
    }

    protected TestingHttpServerRequest getCurrentRequest() {
        return dispatcher.getCurrentRequest();
    }

    protected HttpScope getCurrentSession() {
        return getCurrentRequest().getScope(Scope.SESSION);
    }

    protected OidcClientConfiguration getClientConfig() {
        return clientConfig;
    }

    protected TestingHttpServerResponse getCurrentResponse() {
        try {
            return dispatcher.getCurrentRequest().getResponse();
        } catch (HttpAuthenticationException e) {
            throw new RuntimeException(e);
        }
    }

    class ElytronDispatcher extends Dispatcher {

        volatile TestingHttpServerRequest currentRequest;

        private final HttpServerAuthenticationMechanism mechanism;
        private Dispatcher beforeDispatcher;
        private HttpScope sessionScope;

        public ElytronDispatcher(HttpServerAuthenticationMechanism mechanism, Dispatcher beforeDispatcher) {
            this.mechanism = mechanism;
            this.beforeDispatcher = beforeDispatcher;
        }

        @Override
        public MockResponse dispatch(RecordedRequest serverRequest) throws InterruptedException {
            if (beforeDispatcher != null) {
                MockResponse response = beforeDispatcher.dispatch(serverRequest);

                if (response != null) {
                    return response;
                }
            }

            MockResponse mockResponse = new MockResponse();

            try {
                currentRequest = new TestingHttpServerRequest(serverRequest, sessionScope);

                mechanism.evaluateRequest(currentRequest);

                TestingHttpServerResponse response = currentRequest.getResponse();

                if (Status.COMPLETE.equals(currentRequest.getResult())) {
                    mockResponse.setBody("Welcome, authenticated user");
                    sessionScope = currentRequest.getScope(Scope.SESSION);
                } else {
                    boolean statusSet = response.getStatusCode() > 0;

                    if (statusSet) {
                        mockResponse.setResponseCode(response.getStatusCode());

                        if (response.getLocation() != null) {
                            mockResponse.setHeader(HttpConstants.LOCATION, response.getLocation());
                        }
                    } else {
                        mockResponse.setResponseCode(201);
                        mockResponse.setBody("from " + serverRequest.getPath());
                    }
                }
            } catch (Exception cause) {
                cause.printStackTrace();
                mockResponse.setResponseCode(500);
            }

            return mockResponse;
        }

        public TestingHttpServerRequest getCurrentRequest() {
            return currentRequest;
        }
    }

    protected void configureDispatcher() {
        configureDispatcher(OidcClientConfigurationBuilder.build(getClientConfiguration()), null);
    }

    protected void configureDispatcher(OidcClientConfiguration clientConfig, Dispatcher beforeDispatch) {
        this.clientConfig = clientConfig;
        OidcClientContext oidcClientContext = new OidcClientContext(clientConfig);
        oidcFactory = new OidcMechanismFactory(oidcClientContext);
        HttpServerAuthenticationMechanism mechanism;
        try {
            mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, Collections.emptyMap(), getCallbackHandler());
        } catch (HttpAuthenticationException e) {
            throw new RuntimeException(e);
        }
        dispatcher = new ElytronDispatcher(mechanism, beforeDispatch);
        client.setDispatcher(dispatcher);
    }

    protected void assertUserNotAuthenticated() {
        assertNull(getCurrentSession().getAttachment(OidcAccount.class.getName()));
    }

    protected void assertUserAuthenticated() {
        assertNotNull(getCurrentSession().getAttachment(OidcAccount.class.getName()));
    }
}
