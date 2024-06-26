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

import com.gargoylesoftware.htmlunit.TextPage;
import io.restassured.RestAssured;
import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;
import okhttp3.mockwebserver.MockWebServer;
import org.apache.http.HttpStatus;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.jose4j.jws.AlgorithmIdentifiers.HMAC_SHA256;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.ALICE;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.ALICE_PASSWORD;
import static org.wildfly.security.http.oidc.Oidc.AuthenticationRequestFormat.REQUEST;
import static org.wildfly.security.http.oidc.Oidc.AuthenticationRequestFormat.REQUEST_URI;
import static org.wildfly.security.http.oidc.Oidc.OIDC_NAME;
import static org.wildfly.security.http.oidc.Oidc.OIDC_SCOPE;

/**
 * Tests for cases where the OpenID provider does not support
 * request parameters when sending the request object as a JWT.
 * The OidcClientConfiguration class is mocked to return values
 * indicating a lack of support for request parameters.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */
@RunWith(JMockit.class)
public class MockOidcClientConfiguration extends OidcBaseTest {

    @BeforeClass
    public static void startTestContainers() throws Exception {
        assumeTrue("Docker isn't available, OIDC tests will be skipped", isDockerAvailable());
        KEYCLOAK_CONTAINER = new KeycloakContainer();
        KEYCLOAK_CONTAINER.start();
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TEST_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP, false));
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
    public void testOidcWithRequestParameterUnsupported() throws Exception {
        mockOidcClientConfig();
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST.getValue()), REQUEST.getValue());
    }

    @Test
    public void testOidcWithRequestUriParameterUnsupported() throws Exception {
        mockOidcClientConfig();
        performAuthentication(getOidcConfigurationInputStreamWithRequestParameter(REQUEST_URI.getValue()), REQUEST_URI.getValue());
    }

    public void performAuthentication(InputStream oidcConfig, String requestFormat) throws Exception {
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
        assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, response.getStatusCode());
        assertEquals(Status.NO_AUTH, request.getResult());
        assertFalse(response.getFirstResponseHeaderValue("Location").contains(requestFormat + "="));
        assertTrue(response.getFirstResponseHeaderValue("Location").contains("scope=" + OIDC_SCOPE + "+phone+profile+email"));  //ALL scopes should be added to the URL directly

        client.setDispatcher(createAppResponse(mechanism, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT));

        TextPage page = loginToKeycloak(ALICE, ALICE_PASSWORD, requestUri, response.getLocation(),
                response.getCookies()).click();
        assertTrue(page.getContent().contains(CLIENT_PAGE_TEXT));
    }


    private void mockOidcClientConfig(){
        new MockUp<OidcClientConfiguration>(){
            // Used to indicate that the OpenID provider does not support request_uri parameter
            @Mock
            boolean getRequestUriParameterSupported(){
                return false;
            }

            // Used to indicate that the OpenID provider does not support request parameter
            @Mock
            boolean getRequestParameterSupported(){
                return false;
            }
        };
    }

    private InputStream getOidcConfigurationInputStreamWithRequestParameter(String requestParameter){
        String oidcConfig = "{\n" +
                "    \"client-id\" : \"" + CLIENT_ID + "\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "/" + "\",\n" +
                "    \"public-client\" : \"false\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"authentication-request-format\" : \"" + requestParameter + "\",\n" +
                "    \"request-object-signing-algorithm\" : \"" + HMAC_SHA256 + "\",\n" +
                "    \"scope\" : \"profile email phone\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }
}
