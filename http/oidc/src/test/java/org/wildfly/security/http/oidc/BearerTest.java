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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.ALLOWED_ORIGIN;
import static org.wildfly.security.http.oidc.Oidc.OIDC_NAME;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpStatus;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.WebClient;

import io.restassured.RestAssured;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.QueueDispatcher;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * Tests for bearer only auth.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class BearerTest extends OidcBaseTest {

    private static boolean DIRECT_ACCESS_GRANT_ENABLED = true;
    private static final String BEARER_ONLY_CLIENT_ID = "bearer-client";
    private static final String CORS_CLIENT_ID = "cors-client";
    private static final String SECURED_ENDPOINT = "/service/secured";
    private static final String SECURED_PAGE_TEXT = "Welcome to the secured page!";
    private static final String WRONG_PASSWORD = "WRONG_PASSWORD";

    protected HttpServerAuthenticationMechanismFactory oidcFactory;

    private enum BearerAuthType {
        BEARER,
        QUERY_PARAM,
        BASIC
    }

    @BeforeClass
    public static void startTestContainers() throws Exception {
        assumeTrue("Docker isn't available, OIDC tests will be skipped", isDockerAvailable());
        KEYCLOAK_CONTAINER = new KeycloakContainer();
        KEYCLOAK_CONTAINER.start();
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TEST_REALM, CLIENT_ID, CLIENT_SECRET,
                CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP, DIRECT_ACCESS_GRANT_ENABLED, BEARER_ONLY_CLIENT_ID,
                CORS_CLIENT_ID));
        client = new MockWebServer();
        client.start(CLIENT_PORT);
    }

    private static Dispatcher createAppBearerResponse(HttpServerAuthenticationMechanism mechanism, String clientPageText,
                                                      String expectedError, String originHeader) {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest recordedRequest) throws InterruptedException {
                String path = recordedRequest.getPath();
                if (path.contains("/" + CLIENT_APP + SECURED_ENDPOINT)) {
                    try {
                        String authorizationHeader = recordedRequest.getHeader("Authorization");
                        TestingHttpServerRequest request;
                        if (originHeader != null) {
                            Map<String, List<String>> requestHeaders = new HashMap<>();
                            if (authorizationHeader != null) {
                                requestHeaders.put("Authorization", Collections.singletonList(authorizationHeader));
                            }
                            requestHeaders.put(CorsHeaders.ORIGIN, Collections.singletonList(originHeader));
                            request = new TestingHttpServerRequest(requestHeaders, new URI(recordedRequest.getRequestUrl().toString()), recordedRequest.getMethod());
                        } else {
                            request = new TestingHttpServerRequest(authorizationHeader == null ? null : new String[]{authorizationHeader},
                                    new URI(recordedRequest.getRequestUrl().toString()));
                        }
                        mechanism.evaluateRequest(request);
                        TestingHttpServerResponse response = request.getResponse();
                        int statusCode = response.getStatusCode();
                        if (expectedError != null) {
                            assertTrue(response.getAuthenticateHeader().contains(expectedError));
                            return new MockResponse().setResponseCode(statusCode);
                        } else if (statusCode > 300) {
                            // unexpected error
                            return new MockResponse().setResponseCode(statusCode);
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

    @Test
    public void testSucessfulAuthenticationWithAuthServerUrl() throws Exception {
        performBearerAuthentication(getOidcConfigurationInputStream(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT);
    }

    @Test
    public void testSucessfulAuthenticationWithProviderUrl() throws Exception {
        performBearerAuthentication(getOidcConfigurationInputStreamWithProviderUrl(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT);
    }

    @Test
    public void testWrongToken() throws Exception {
        String wrongToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJrNmhQYTdHdmdrajdFdlhLeFAtRjFLZkNSUk85Q3kwNC04YzFqTERWOXNrIn0.eyJleHAiOjE2NTc2NjExODksImlhdCI6MTY1NzY2MTEyOSwianRpIjoiZThiZGQ3MWItYTA2OC00Mjc3LTkyY2UtZWJkYmU2MDVkMzBhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOlsibXlyZWFsbS1yZWFsbSIsIm1hc3Rlci1yZWFsbSIsImFjY291bnQiXSwic3ViIjoiZTliOGE2OWItM2RlNy00ZDYzLWFjYmItMmYyNTRhMDM1MjVkIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVzdC13ZWJhcHAiLCJzZXNzaW9uX3N0YXRlIjoiMTQ1OTdhMmUtOGM1Ni00YzkwLWI3NjAtZWFjYzczNWU1Zjc1IiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJjcmVhdGUtcmVhbG0iLCJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwiYWRtaW4iLCJ1bWFfYXV0aG9yaXphdGlvbiIsInVzZXIiXX0sInJlc291cmNlX2FjY2VzcyI6eyJteXJlYWxtLXJlYWxtIjp7InJvbGVzIjpbInZpZXctcmVhbG0iLCJ2aWV3LWlkZW50aXR5LXByb3ZpZGVycyIsIm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnMiLCJpbXBlcnNvbmF0aW9uIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInF1ZXJ5LXJlYWxtcyIsInZpZXctYXV0aG9yaXphdGlvbiIsInF1ZXJ5LWNsaWVudHMiLCJxdWVyeS11c2VycyIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJ2aWV3LWV2ZW50cyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtYXV0aG9yaXphdGlvbiIsIm1hbmFnZS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIl19LCJtYXN0ZXItcmVhbG0iOnsicm9sZXMiOlsidmlldy1yZWFsbSIsInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsInNpZCI6IjE0NTk3YTJlLThjNTYtNGM5MC1iNzYwLWVhY2M3MzVlNWY3NSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2UifQ.hVj6SG-aTcDYhifdljpiBcz4ShCHej3h_4-82rgX0s_oJ-En68Cqt-_DgJLtMdr6dW_gQFFCPYBJfEGvZ8L6b_TwzbdLxyrQrKTOpeG0KJ8VAFlbWum9B1vvES_sav1Gj1sQHlV621EaLISYz7pnknuQEvrB7liJFRRjN9SH30AsAJy6nmKTDHGZ6Eegkveqd_7POaKfsHS3Z0-SGyL5GClXv9yZ1l5Y4VH-rrMUztLPCFH5bJ319-m-7sgizvV-C2EcM37XVAtPRVQbJNRW0wVmLEJKMuLYVnjS1Wn5eU_qnBvVMEaENNG3TzNd6b4YmxMFHFf9tnkb3wkDzdrRTA";
        performBearerAuthentication(getOidcConfigurationInputStreamWithProviderUrl(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT, wrongToken, BearerAuthType.BEARER);
    }

    @Test
    public void testInvalidToken() throws Exception {
        performBearerAuthentication(getOidcConfigurationInputStreamWithProviderUrl(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT, "INVALID_TOKEN", BearerAuthType.BEARER);
    }

    @Test
    public void testNoTokenProvidedWithAuthServerUrl() throws Exception {
        accessAppWithoutToken(SECURED_ENDPOINT, getOidcConfigurationInputStream());
    }

    @Test
    public void testNoTokenProvidedWithProviderUrl() throws Exception {
        accessAppWithoutToken(SECURED_ENDPOINT, getOidcConfigurationInputStreamWithProviderUrl());
    }

    @Test
    public void testTokenProvidedBearerOnlyNotSet() throws Exception {
        // ensure we still make use of the bearer token
        performBearerAuthentication(getOidcConfigurationInputStreamWithoutBearerOnly(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT);
    }

    @Test
    public void testTokenNotProvidedBearerOnlyNotSet() throws Exception {
        // ensure the regular OIDC flow takes place
        accessAppWithoutToken("", getRegularOidcConfigurationInputStream());
    }

    /**
     * Tests that pass the bearer token to use via an access_token query param.
     */

    @Test
    public void testValidTokenViaQueryParameter() throws Exception {
        performBearerAuthentication(getOidcConfigurationInputStreamWithProviderUrl(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT, null, BearerAuthType.QUERY_PARAM);
    }

    @Test
    public void testWrongTokenViaQueryParameter() throws Exception {
        String wrongToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJrNmhQYTdHdmdrajdFdlhLeFAtRjFLZkNSUk85Q3kwNC04YzFqTERWOXNrIn0.eyJleHAiOjE2NTc2NjExODksImlhdCI6MTY1NzY2MTEyOSwianRpIjoiZThiZGQ3MWItYTA2OC00Mjc3LTkyY2UtZWJkYmU2MDVkMzBhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOlsibXlyZWFsbS1yZWFsbSIsIm1hc3Rlci1yZWFsbSIsImFjY291bnQiXSwic3ViIjoiZTliOGE2OWItM2RlNy00ZDYzLWFjYmItMmYyNTRhMDM1MjVkIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVzdC13ZWJhcHAiLCJzZXNzaW9uX3N0YXRlIjoiMTQ1OTdhMmUtOGM1Ni00YzkwLWI3NjAtZWFjYzczNWU1Zjc1IiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJjcmVhdGUtcmVhbG0iLCJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwiYWRtaW4iLCJ1bWFfYXV0aG9yaXphdGlvbiIsInVzZXIiXX0sInJlc291cmNlX2FjY2VzcyI6eyJteXJlYWxtLXJlYWxtIjp7InJvbGVzIjpbInZpZXctcmVhbG0iLCJ2aWV3LWlkZW50aXR5LXByb3ZpZGVycyIsIm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnMiLCJpbXBlcnNvbmF0aW9uIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInF1ZXJ5LXJlYWxtcyIsInZpZXctYXV0aG9yaXphdGlvbiIsInF1ZXJ5LWNsaWVudHMiLCJxdWVyeS11c2VycyIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJ2aWV3LWV2ZW50cyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtYXV0aG9yaXphdGlvbiIsIm1hbmFnZS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIl19LCJtYXN0ZXItcmVhbG0iOnsicm9sZXMiOlsidmlldy1yZWFsbSIsInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsInNpZCI6IjE0NTk3YTJlLThjNTYtNGM5MC1iNzYwLWVhY2M3MzVlNWY3NSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2UifQ.hVj6SG-aTcDYhifdljpiBcz4ShCHej3h_4-82rgX0s_oJ-En68Cqt-_DgJLtMdr6dW_gQFFCPYBJfEGvZ8L6b_TwzbdLxyrQrKTOpeG0KJ8VAFlbWum9B1vvES_sav1Gj1sQHlV621EaLISYz7pnknuQEvrB7liJFRRjN9SH30AsAJy6nmKTDHGZ6Eegkveqd_7POaKfsHS3Z0-SGyL5GClXv9yZ1l5Y4VH-rrMUztLPCFH5bJ319-m-7sgizvV-C2EcM37XVAtPRVQbJNRW0wVmLEJKMuLYVnjS1Wn5eU_qnBvVMEaENNG3TzNd6b4YmxMFHFf9tnkb3wkDzdrRTA";
        performBearerAuthentication(getOidcConfigurationInputStreamWithProviderUrl(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT, wrongToken, BearerAuthType.QUERY_PARAM);
    }

    @Test
    public void testInvalidTokenViaQueryParameter() throws Exception {
        performBearerAuthentication(getOidcConfigurationInputStreamWithProviderUrl(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT, "INVALID_TOKEN", BearerAuthType.QUERY_PARAM);
    }

    /**
     * Tests that rely on obtaining the bearer token to use from credentials obtained from basic auth.
     */

    @Test
    public void testBasicAuthenticationWithoutEnableBasicAuthSet() throws Exception {
        accessAppWithoutToken(SECURED_ENDPOINT, getOidcConfigurationInputStream(), BearerAuthType.BASIC, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD);
    }

    @Test
    public void testBasicAuthenticationWithoutEnableBasicAuthSetAndWithoutBearerOnlySet() throws Exception {
        // ensure the regular OIDC flow takes place
        accessAppWithoutToken("", getRegularOidcConfigurationInputStream(), BearerAuthType.BASIC, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD);
    }

    @Test
    public void testValidCredentialsBasicAuthentication() throws Exception {
        performBearerAuthentication(getOidcConfigurationInputStreamWithEnableBasicAuth(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT, null, BearerAuthType.BASIC);
    }

    @Test
    public void testInvalidCredentialsBasicAuthentication() throws Exception {
        accessAppWithoutToken(SECURED_ENDPOINT, getOidcConfigurationInputStreamWithEnableBasicAuth(), BearerAuthType.BASIC, KeycloakConfiguration.ALICE, WRONG_PASSWORD);
    }

    /**
     * Tests that simulate CORS preflight requests.
     */

    @Test
    public void testCorsRequestWithEnableCors() throws Exception {
        performBearerAuthenticationCorsRequest(getOidcConfigurationInputStreamWithEnableCors(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT, null, ALLOWED_ORIGIN);
    }

    @Test
    public void testCorsRequestWithEnableCorsWithWrongToken() throws Exception {
        String wrongToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJrNmhQYTdHdmdrajdFdlhLeFAtRjFLZkNSUk85Q3kwNC04YzFqTERWOXNrIn0.eyJleHAiOjE2NTc2NjExODksImlhdCI6MTY1NzY2MTEyOSwianRpIjoiZThiZGQ3MWItYTA2OC00Mjc3LTkyY2UtZWJkYmU2MDVkMzBhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOlsibXlyZWFsbS1yZWFsbSIsIm1hc3Rlci1yZWFsbSIsImFjY291bnQiXSwic3ViIjoiZTliOGE2OWItM2RlNy00ZDYzLWFjYmItMmYyNTRhMDM1MjVkIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVzdC13ZWJhcHAiLCJzZXNzaW9uX3N0YXRlIjoiMTQ1OTdhMmUtOGM1Ni00YzkwLWI3NjAtZWFjYzczNWU1Zjc1IiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJjcmVhdGUtcmVhbG0iLCJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwiYWRtaW4iLCJ1bWFfYXV0aG9yaXphdGlvbiIsInVzZXIiXX0sInJlc291cmNlX2FjY2VzcyI6eyJteXJlYWxtLXJlYWxtIjp7InJvbGVzIjpbInZpZXctcmVhbG0iLCJ2aWV3LWlkZW50aXR5LXByb3ZpZGVycyIsIm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnMiLCJpbXBlcnNvbmF0aW9uIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInF1ZXJ5LXJlYWxtcyIsInZpZXctYXV0aG9yaXphdGlvbiIsInF1ZXJ5LWNsaWVudHMiLCJxdWVyeS11c2VycyIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJ2aWV3LWV2ZW50cyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtYXV0aG9yaXphdGlvbiIsIm1hbmFnZS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIl19LCJtYXN0ZXItcmVhbG0iOnsicm9sZXMiOlsidmlldy1yZWFsbSIsInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsInNpZCI6IjE0NTk3YTJlLThjNTYtNGM5MC1iNzYwLWVhY2M3MzVlNWY3NSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2UifQ.hVj6SG-aTcDYhifdljpiBcz4ShCHej3h_4-82rgX0s_oJ-En68Cqt-_DgJLtMdr6dW_gQFFCPYBJfEGvZ8L6b_TwzbdLxyrQrKTOpeG0KJ8VAFlbWum9B1vvES_sav1Gj1sQHlV621EaLISYz7pnknuQEvrB7liJFRRjN9SH30AsAJy6nmKTDHGZ6Eegkveqd_7POaKfsHS3Z0-SGyL5GClXv9yZ1l5Y4VH-rrMUztLPCFH5bJ319-m-7sgizvV-C2EcM37XVAtPRVQbJNRW0wVmLEJKMuLYVnjS1Wn5eU_qnBvVMEaENNG3TzNd6b4YmxMFHFf9tnkb3wkDzdrRTA";
        performBearerAuthenticationCorsRequest(getOidcConfigurationInputStreamWithEnableCors(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT, wrongToken, ALLOWED_ORIGIN);
    }

    @Test
    public void testCorsRequestWithEnableCorsWithInvalidToken() throws Exception {
        performBearerAuthenticationCorsRequest(getOidcConfigurationInputStreamWithEnableCors(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT, "INVALID_TOKEN", ALLOWED_ORIGIN);
    }

    @Test
    public void testCorsRequestWithEnableCorsInvalidOrigin() throws Exception {
        performBearerAuthenticationCorsRequest(getOidcConfigurationInputStreamWithEnableCors(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT, null, "http://invalidorigin");
    }

    @Test
    public void testCorsRequestWithoutEnableCors() throws Exception {
        performBearerAuthenticationCorsRequest(getOidcConfigurationInputStream(), SECURED_ENDPOINT, KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                SECURED_PAGE_TEXT, null, ALLOWED_ORIGIN);
    }

    private void performBearerAuthentication(InputStream oidcConfig, String endpoint, String username, String password, String clientPageText) throws Exception {
        performBearerAuthentication(oidcConfig, endpoint, username, password, clientPageText, null, BearerAuthType.BEARER);
    }

    private void performBearerAuthentication(InputStream oidcConfig, String endpoint, String username, String password,
                                             String clientPageText, String bearerToken, BearerAuthType bearerAuthType) throws Exception {
        try {
            Map<String, Object> props = new HashMap<>();
            OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(oidcConfig);
            assertEquals(OidcClientConfiguration.RelativeUrlsUsed.NEVER, oidcClientConfiguration.getRelativeUrls());

            OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
            oidcFactory = new OidcMechanismFactory(oidcClientContext);
            HttpServerAuthenticationMechanism mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler());

            if (bearerToken != null) { // going to pass an invalid token
                client.setDispatcher(createAppBearerResponse(mechanism, clientPageText, "invalid_token", null));
            } else {
                client.setDispatcher(createAppBearerResponse(mechanism, clientPageText, null, null));
            }

            URI requestUri;
            WebClient webClient = getWebClient();
            switch (bearerAuthType) {
                case QUERY_PARAM:
                    if (bearerToken == null) {
                        // obtain a bearer token and then try accessing the endpoint with a query param specified
                        requestUri = new URI(getClientUrl() + endpoint + "?access_token="
                                + KeycloakConfiguration.getAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl(), TEST_REALM, username,
                                password, CLIENT_ID, CLIENT_SECRET));
                    } else {
                        // try accessing the endpoint with the given bearer token specified using a query param
                        requestUri = new URI(getClientUrl() + endpoint + "?access_token=" + bearerToken);
                    }
                    break;
                case BASIC:
                    webClient.addRequestHeader("Authorization",
                            "Basic " + CodePointIterator.ofString(username + ":" + password).asUtf8().base64Encode().drainToString());
                    requestUri = new URI(getClientUrl() + endpoint);
                    break;
                default:
                    if (bearerToken == null) {
                        // obtain a bearer token and then try accessing the endpoint with the Authorization header specified
                        webClient.addRequestHeader("Authorization", "Bearer " + KeycloakConfiguration.getAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl(), TEST_REALM, username,
                                password, CLIENT_ID, CLIENT_SECRET));
                    } else {
                        // try accessing the endpoint with the given bearer token specified using the Authorization header
                        webClient.addRequestHeader("Authorization", "Bearer " + bearerToken);
                    }
                    requestUri = new URI(getClientUrl() + endpoint);
            }

            if (bearerToken == null) {
                TextPage page = webClient.getPage(requestUri.toURL());
                assertEquals(HttpStatus.SC_OK, page.getWebResponse().getStatusCode());
                assertTrue(page.getContent().contains(clientPageText));
            } else {
                try {
                    webClient.getPage(requestUri.toURL());
                    fail("Expected exception not thrown");
                } catch (FailingHttpStatusCodeException e) {
                    assertEquals(HttpStatus.SC_UNAUTHORIZED, e.getStatusCode());
                }
            }
        } finally {
            client.setDispatcher(new QueueDispatcher());
        }
    }

    private void performBearerAuthenticationCorsRequest(InputStream oidcConfig, String endpoint, String username, String password,
                                             String clientPageText, String bearerToken, String originHeader) throws Exception {
        try {
            Map<String, Object> props = new HashMap<>();
            OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(oidcConfig);
            assertEquals(OidcClientConfiguration.RelativeUrlsUsed.NEVER, oidcClientConfiguration.getRelativeUrls());

            OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
            oidcFactory = new OidcMechanismFactory(oidcClientContext);
            HttpServerAuthenticationMechanism mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler());

            URI requestUri = new URI(getClientUrl() + endpoint);

            // simulate preflight request
            Map<String, List<String>> requestHeaders = new HashMap<>();
            requestHeaders.put(CorsHeaders.ORIGIN, Collections.singletonList(originHeader));
            requestHeaders.put(CorsHeaders.ACCESS_CONTROL_REQUEST_HEADERS, Collections.singletonList("authorization"));
            requestHeaders.put(CorsHeaders.ACCESS_CONTROL_REQUEST_METHOD, Collections.singletonList(HttpMethod.GET.name()));
            TestingHttpServerRequest request = new TestingHttpServerRequest(requestHeaders, requestUri, HttpMethod.OPTIONS.name());
            mechanism.evaluateRequest(request);
            TestingHttpServerResponse response = request.getResponse();

            if (oidcClientConfiguration.isCors()) {
                assertTrue(Boolean.valueOf(response.getFirstResponseHeaderValue(CorsHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS)));
                assertEquals("authorization", response.getFirstResponseHeaderValue(CorsHeaders.ACCESS_CONTROL_ALLOW_HEADERS));
                assertEquals(HttpMethod.GET.name(), response.getFirstResponseHeaderValue(CorsHeaders.ACCESS_CONTROL_ALLOW_METHODS));
                assertEquals(originHeader, response.getFirstResponseHeaderValue(CorsHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));

                if (bearerToken != null) { // going to pass an invalid token
                    client.setDispatcher(createAppBearerResponse(mechanism, clientPageText, "invalid_token", originHeader));
                } else {
                    client.setDispatcher(createAppBearerResponse(mechanism, clientPageText, null, originHeader));
                }

                WebClient webClient = getWebClient();
                webClient.addRequestHeader(CorsHeaders.ORIGIN, originHeader);
                if (bearerToken == null) {
                    webClient.addRequestHeader("Authorization", "Bearer " + KeycloakConfiguration.getAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl(), TEST_REALM, username,
                            password, CORS_CLIENT_ID, CLIENT_SECRET));
                } else {
                    webClient.addRequestHeader("Authorization", "Bearer " + bearerToken);
                }
                if (bearerToken == null) {
                    try {
                        TextPage page = webClient.getPage(requestUri.toURL());
                        assertEquals(HttpStatus.SC_OK, page.getWebResponse().getStatusCode());
                        assertTrue(page.getContent().contains(clientPageText));
                    } catch (FailingHttpStatusCodeException e) {
                        assertFalse(originHeader.equals(ALLOWED_ORIGIN));
                        assertEquals(HttpStatus.SC_FORBIDDEN, e.getStatusCode());
                    }
                } else {
                    try {
                        webClient.getPage(requestUri.toURL());
                        fail("Expected exception not thrown");
                    } catch (FailingHttpStatusCodeException e) {
                        assertEquals(HttpStatus.SC_UNAUTHORIZED, e.getStatusCode());
                    }
                }
            } else {
                assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
                if (oidcClientConfiguration.getRealm() != null) {
                    // if we have a keycloak realm configured, its name should appear in the challenge
                    assertEquals("Bearer realm=\"" + TEST_REALM + "\"", response.getAuthenticateHeader());
                } else {
                    assertEquals("Bearer", response.getAuthenticateHeader());
                }
            }
        } finally {
            client.setDispatcher(new QueueDispatcher());
        }
    }

    private void accessAppWithoutToken(String endpoint, InputStream oidcConfigInputStream) throws Exception {
        accessAppWithoutToken(endpoint, oidcConfigInputStream, null, null, null);
    }

    private void accessAppWithoutToken(String endpoint, InputStream oidcConfigInputStream, BearerAuthType bearerAuthType, String username, String password) throws Exception {
        Map<String, Object> props = new HashMap<>();
        OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(oidcConfigInputStream);
        assertEquals(OidcClientConfiguration.RelativeUrlsUsed.NEVER, oidcClientConfiguration.getRelativeUrls());

        OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
        oidcFactory = new OidcMechanismFactory(oidcClientContext);
        HttpServerAuthenticationMechanism mechanism = oidcFactory.createAuthenticationMechanism(OIDC_NAME, props, getCallbackHandler());

        URI requestUri = new URI(getClientUrl() + endpoint);
        TestingHttpServerRequest request;
        if (bearerAuthType == BearerAuthType.BASIC) {
            request = new TestingHttpServerRequest(new String[] {"Basic "
                    + CodePointIterator.ofString(username + ":" + password).asUtf8().base64Encode().drainToString()}, requestUri);
        } else {
            request = new TestingHttpServerRequest(null, requestUri); // no bearer token specified
        }
        mechanism.evaluateRequest(request);
        TestingHttpServerResponse response = request.getResponse();

        if (oidcClientConfiguration.isBearerOnly() || oidcClientConfiguration.isEnableBasicAuth()) {
            assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
            String authenticateHeader = response.getAuthenticateHeader();
            if ((bearerAuthType == BearerAuthType.BASIC) && password.equals(WRONG_PASSWORD)) {
                assertTrue(authenticateHeader.startsWith("Bearer error=\"" + "no_token" + "\""));
                assertTrue(authenticateHeader.contains("error_description"));
                assertTrue(authenticateHeader.contains(String.valueOf(HttpStatus.SC_UNAUTHORIZED)));
            } else if (oidcClientConfiguration.getRealm() != null) {
                // if we have a keycloak realm configured, its name should appear in the challenge
                assertEquals("Bearer realm=\"" + TEST_REALM + "\"", authenticateHeader);
            } else {
                assertEquals("Bearer", authenticateHeader);
            }
        } else {
            // no token provided and bearer-only is not configured, should end up in the OIDC flow
            assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, response.getStatusCode());
            assertEquals(Status.NO_AUTH, request.getResult());
            try {
                // browser login should succeed
                client.setDispatcher(createAppResponse(mechanism, HttpStatus.SC_MOVED_TEMPORARILY, getClientUrl(), CLIENT_PAGE_TEXT));
                TextPage page = loginToKeycloak(KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD, requestUri, response.getLocation(),
                        response.getCookies()).click();
                assertTrue(page.getContent().contains(CLIENT_PAGE_TEXT));
            } finally {
                client.setDispatcher(new QueueDispatcher());
            }
        }
    }

    private InputStream getOidcConfigurationInputStream() {
        return getOidcConfigurationInputStream(KEYCLOAK_CONTAINER.getAuthServerUrl());
    }

    private InputStream getOidcConfigurationInputStream(String authServerUrl) {
        String oidcConfig = "{\n" +
                "    \"realm\" : \"" + TEST_REALM + "\",\n" +
                "    \"resource\" : \"" + BEARER_ONLY_CLIENT_ID + "\",\n" +
                "    \"auth-server-url\" : \"" + authServerUrl + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"bearer-only\" : \"true\"\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    protected InputStream getOidcConfigurationInputStreamWithProviderUrl() {
        String oidcConfig = "{\n" +
                "    \"client-id\" : \"" + BEARER_ONLY_CLIENT_ID + "\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"bearer-only\" : \"true\"\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithoutBearerOnly() {
        String oidcConfig = "{\n" +
                "    \"client-id\" : \"" + BEARER_ONLY_CLIENT_ID + "\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\"\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getRegularOidcConfigurationInputStream() {
        String oidcConfig = "{\n" +
                "    \"client-id\" : \"" + CLIENT_ID + "\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithEnableBasicAuth() {
        String oidcConfig = "{\n" +
                "    \"client-id\" : \"" + CLIENT_ID + "\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"enable-basic-auth\" : \"true\",\n" +
                "    \"credentials\" : {\n" +
                "        \"secret\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream getOidcConfigurationInputStreamWithEnableCors() {
        String oidcConfig = "{\n" +
                "    \"client-id\" : \"" + BEARER_ONLY_CLIENT_ID + "\",\n" +
                "    \"provider-url\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM + "\",\n" +
                "    \"ssl-required\" : \"EXTERNAL\",\n" +
                "    \"enable-cors\" : \"true\",\n" +
                "    \"bearer-only\" : \"true\"\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }
}