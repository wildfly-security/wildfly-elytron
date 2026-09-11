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

import io.restassured.RestAssured;
import okhttp3.mockwebserver.MockWebServer;
import org.apache.http.HttpStatus;
import org.jboss.logmanager.ExtLogRecord;
import org.jboss.logmanager.LogContext;
import org.jboss.logmanager.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.LoggerFactory;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.NginxContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.DockerImageName;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assume.assumeTrue;
import static org.wildfly.common.Assert.assertNotNull;
import static org.wildfly.security.http.oidc.Oidc.AUTH_SERVER_URL;
import static org.wildfly.security.http.oidc.Oidc.CREDENTIALS;
import static org.wildfly.security.http.oidc.Oidc.PUBLIC_CLIENT;
import static org.wildfly.security.http.oidc.Oidc.REALM;
import static org.wildfly.security.http.oidc.Oidc.RESOURCE;
import static org.wildfly.security.http.oidc.Oidc.SSL_REQUIRED;

/**
 * Tests for relative URL in auth-server-url parameter. These tests use nginx proxy server to access the KC instance and client instance
 * auth-server-url is configured to be relative, so the KC instance URL will be resolved from the incoming Forwarded/Host headers.
 *
 */
public class RelativePathAsAuthServerUrlTest extends OidcBaseTest {

    public static final String NGINX_IMAGE = "nginx:1.20";
    protected static Network network = null;
    private NginxContainer<?> nginxContainer;

    @BeforeClass
    public static void startTestContainers() throws Exception {
        assumeTrue("Docker isn't available, OIDC tests will be skipped", isDockerAvailable());
        System.setProperty("TESTCONTAINERS_HOST_OVERRIDE", "localhost");
        Testcontainers.exposeHostPorts(CLIENT_PORT);
    }

    private static void prepareKeycloakAndClient(String relativeUrl) throws Exception {
        network = Network.newNetwork();
        KEYCLOAK_CONTAINER = new KeycloakContainer(relativeUrl)
                .withNetwork(network)
                .withNetworkAliases("keycloak")
                .withAccessToHost(true);
        KEYCLOAK_CONTAINER.start();
        if (client == null) {
            client = new MockWebServer();
            client.start(CLIENT_PORT);
        }
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TEST_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP, false, true));
    }

    @AfterClass
    public static void generalCleanup() throws Exception {
        System.clearProperty("oidc.provider.url");
        if (client != null) {
            client.shutdown();
        }
    }

    @After
    public void afterMethod() {
        if (nginxContainer != null) {
            nginxContainer.stop();
            nginxContainer = null;
        }

        if (KEYCLOAK_CONTAINER != null) {
            RestAssured
                    .given()
                    .auth().oauth2(KeycloakConfiguration.getAdminAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl()))
                    .when()
                    .delete(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/admin/realms/" + TEST_REALM).then().statusCode(204);
            KEYCLOAK_CONTAINER.stop();
            KEYCLOAK_CONTAINER = null;
        }

        if (network != null) {
            network.close();
            network = null;
        }
    }

    @Test
    public void testSuccessfulAuthenticationWithRelativeAuthServerUrl() throws Exception {
        prepareKeycloakAndClient(null);
        URL proxyHttpUrl = startProxyAndGetProxyPort(8060, "http://keycloak:8080/realms/WildFly/");
        performAuthentication(getOidcConfigurationInputStream(CLIENT_SECRET, "/"), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, true, proxyHttpUrl + "/" + CLIENT_APP, proxyHttpUrl + "/" + CLIENT_APP, CLIENT_PAGE_TEXT);
    }

    @Test
    public void testSuccessfulAuthenticationWithRelativeAuthServerUrlSubUrl() throws Exception {
        prepareKeycloakAndClient("keycloak");
        URL proxyHttpUrl = startProxyAndGetProxyPort(8060, "http://keycloak:8080/keycloak/realms/WildFly/");
        performAuthentication(getOidcConfigurationInputStream(CLIENT_SECRET, "/keycloak"), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_MOVED_TEMPORARILY, true, proxyHttpUrl + "/" + CLIENT_APP, proxyHttpUrl + "/" + CLIENT_APP, CLIENT_PAGE_TEXT);
    }

    @Test
    public void testUnauthenticatedClientWithRelativeAuthServerUrl() throws Exception {
        prepareKeycloakAndClient("keycloak");
        URL proxyHttpUrl = startProxyAndGetProxyPort(8060, "http://keycloak:8080/keycloak/realms/WildFly/");

        performAuthentication(getOidcConfigurationInputStream("incorrect_client_secret", "/keycloak"), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, HttpStatus.SC_FORBIDDEN, true, proxyHttpUrl + "/" + CLIENT_APP, null, "Forbidden");
    }

    @Test
    public void testWrongRelativeAuthServerUrl() throws Exception {
        prepareKeycloakAndClient(null);
        URL proxyHttpUrl = startProxyAndGetProxyPort(8060, "http://keycloak:8080/realms/WildFly/");

        performAuthentication(getOidcConfigurationInputStream(CLIENT_SECRET, "/wrong_relative_url_endpoint"), KeycloakConfiguration.ALICE, KeycloakConfiguration.ALICE_PASSWORD,
                true, -1, proxyHttpUrl + "/" + CLIENT_APP, null, null, null, false, false, true, false);
    }

    @Test
    public void testUnitRelativeAuthServerUrlIsResolvedCorrectly() throws Exception {
        try (WarnCapture warnCapture = attachOidcWarnCapture()) {
            OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(getOidcConfigurationInputStream(CLIENT_SECRET, "/keycloak"));
            assertEquals(OidcClientConfiguration.RelativeUrlsUsed.ALWAYS, oidcClientConfiguration.getRelativeUrls());
            OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
            OidcClientConfiguration oidcClientConfigurationWithResolvedUrls = oidcClientContext.resolveUrls(oidcClientConfiguration,
                    // the request will contain "Host" header with value "localhost:1234"
                    new OidcHttpFacade(new TestingHttpServerRequest(null, new URI("http://localhost:1234/keycloak/myTestApp")), oidcClientContext, null));
            // relative URL is taken from HTTP "Host" header of incoming request
            assertEquals("http://localhost:1234/keycloak", oidcClientConfigurationWithResolvedUrls.getAuthServerBaseUrl());

            oidcClientConfigurationWithResolvedUrls = oidcClientContext.resolveUrls(oidcClientConfiguration,
                    // the request will contain "Host" header with value "test.com:4567"
                    new OidcHttpFacade(new TestingHttpServerRequest(null, new URI("http://test.com:4567/keycloak/myTestApp")), oidcClientContext, null));
            // relative URL is taken from HTTP "Host" header of incoming request
            assertEquals("http://test.com:4567/keycloak", oidcClientConfigurationWithResolvedUrls.getAuthServerBaseUrl());

            warnCapture.assertNoEly23005UnableToLoadMetadata();
        }
    }

    /**
     * When relative auth-server-url is provided, resolving the request must not trigger an OpenID discovery attempt.
     */
    @Test
    public void testUnitRelativeAuthServerUrlWithProviderUrlDoesNotLogEly23005() throws Exception {
        try (WarnCapture warnCapture = attachOidcWarnCapture()) {
            OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(
                    getOidcConfigurationInputStream(CLIENT_SECRET, "/keycloak", "/oidc"));
            assertEquals(OidcClientConfiguration.RelativeUrlsUsed.ALWAYS, oidcClientConfiguration.getRelativeUrls());
            OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
            OidcClientConfiguration resolved = oidcClientContext.resolveUrls(oidcClientConfiguration,
                    new OidcHttpFacade(new TestingHttpServerRequest(null, new URI("http://localhost:1234/keycloak/myTestApp")), oidcClientContext, null));
            assertEquals("http://localhost:1234/keycloak", resolved.getAuthServerBaseUrl());
            warnCapture.assertNoEly23005UnableToLoadMetadata();
        }
    }

    private URL startProxyAndGetProxyPort(int proxyPort, String keycloakUrl) throws MalformedURLException {
        Slf4jLogConsumer logConsumer = new Slf4jLogConsumer(LoggerFactory.getLogger(RelativePathAsAuthServerUrlTest.class));
        List<String> portBindings = new ArrayList<>();
        portBindings.add(proxyPort + ":80");

        nginxContainer = new NginxContainer<>(DockerImageName.parse(NGINX_IMAGE))
                .withNetwork(network)
                .withEnv("KC_ENDPOINT", keycloakUrl)
                .withEnv("PROXY_PORT", String.valueOf(proxyPort))
                .withEnv("CLIENT_PORT", String.valueOf(CLIENT_PORT))
                .withExposedPorts(80)
                .withClasspathResourceMapping("org/wildfly/security/http/oidc/nginx.conf", "/etc/nginx/templates/default.conf.template", BindMode.READ_WRITE)
                .withAccessToHost(true);
        nginxContainer.setPortBindings(portBindings);
        nginxContainer.start();
        nginxContainer.followOutput(logConsumer);
        URL proxyHttpUrl = nginxContainer.getBaseUrl("http", 80);
        assertNotNull(proxyHttpUrl);

        return proxyHttpUrl;
    }

    private InputStream getOidcConfigurationInputStream(String clientSecret, String authServerUrl) {
        return getOidcConfigurationInputStream(clientSecret, authServerUrl, null);
    }

    private InputStream getOidcConfigurationInputStream(String clientSecret, String authServerUrl, String providerUrl) {
        String providerEntry = providerUrl != null
                ? ",\n    \"" + "provider-url" + "\" : \"" + providerUrl + "\""
                : "";
        String oidcConfig = "{\n" +
                "    \"" + REALM + "\" : \"" + TEST_REALM + "\",\n" +
                "    \"" + RESOURCE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + AUTH_SERVER_URL + "\" : \"" + authServerUrl + "\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + Oidc.ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + clientSecret + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

    private static final String OIDC_HTTP_LOG_CATEGORY = "org.wildfly.security.http.oidc";

    private static WarnCapture attachOidcWarnCapture() {
        final List<LogRecord> records = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                    records.add(record);
                }
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        handler.setLevel(Level.ALL);
        Logger logger = LogContext.getLogContext().getLogger(OIDC_HTTP_LOG_CATEGORY);
        logger.addHandler(handler);
        return new WarnCapture(logger, handler, records);
    }

    private static final class WarnCapture implements AutoCloseable {
        private final Logger logger;
        private final Handler handler;
        private final List<LogRecord> records;

        WarnCapture(Logger logger, Handler handler, List<LogRecord> records) {
            this.logger = logger;
            this.handler = handler;
            this.records = records;
        }

        @Override
        public void close() {
            logger.removeHandler(handler);
        }

        void assertNoEly23005UnableToLoadMetadata() {
            for (LogRecord r : records) {
                String text = formatRecord(r);
                assertFalse("ELY23005 (unable to load provider metadata) must not be logged when resolving relative URLs; got: " + text,
                        text.contains("ELY23005") || text.contains("Unable to load OpenID provider metadata"));
            }
        }
    }

    private static String formatRecord(LogRecord r) {
        if (r instanceof ExtLogRecord) {
            return ((ExtLogRecord) r).getFormattedMessage();
        }
        String msg = r.getMessage();
        Object[] params = r.getParameters();
        if (msg != null && params != null && params.length > 0) {
            try {
                return String.format(msg, params);
            } catch (Exception e) {
                return msg;
            }
        }
        return msg != null ? msg : "";
    }
}
