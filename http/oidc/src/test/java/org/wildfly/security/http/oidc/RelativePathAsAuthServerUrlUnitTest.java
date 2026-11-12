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

import org.jboss.logmanager.ExtLogRecord;
import org.jboss.logmanager.LogContext;
import org.jboss.logmanager.Logger;
import org.junit.Test;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.wildfly.security.http.oidc.Oidc.AUTH_SERVER_URL;
import static org.wildfly.security.http.oidc.Oidc.CREDENTIALS;
import static org.wildfly.security.http.oidc.Oidc.OIDC_NAME;
import static org.wildfly.security.http.oidc.Oidc.PUBLIC_CLIENT;
import static org.wildfly.security.http.oidc.Oidc.REALM;
import static org.wildfly.security.http.oidc.Oidc.RESOURCE;
import static org.wildfly.security.http.oidc.Oidc.SSL_REQUIRED;

/**
 * Unit tests for relative URL resolution in OIDC authentication.
 * These tests do not require Docker containers and test the URL resolution logic directly.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class RelativePathAsAuthServerUrlUnitTest extends OidcBaseTest {
    @Test
    public void testUnitRelativeAuthServerUrlIsResolvedCorrectly() throws Exception {
        OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(
            getOidcConfigurationInputStream(CLIENT_SECRET, "/keycloak")
        );
        assertEquals(OidcClientConfiguration.RelativeUrlsUsed.ALWAYS, oidcClientConfiguration.getRelativeUrls());
        OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
        // Test with localhost:1234
        OidcClientConfiguration oidcClientConfigurationWithResolvedUrls = oidcClientContext.resolveUrls(
            oidcClientConfiguration,
            new OidcHttpFacade(
                new TestingHttpServerRequest(null, new URI("http://localhost:1234/keycloak/myTestApp")),
                oidcClientContext,
                null
            )
        );
        // relative URL is taken from HTTP "Host" header of incoming request
        assertEquals("http://localhost:1234/keycloak", oidcClientConfigurationWithResolvedUrls.getAuthServerBaseUrl());
        // Test with test.com:4567
        oidcClientConfigurationWithResolvedUrls = oidcClientContext.resolveUrls(
            oidcClientConfiguration,
            new OidcHttpFacade(
                new TestingHttpServerRequest(null, new URI("http://test.com:4567/keycloak/myTestApp")),
                oidcClientContext,
                null
            )
        );
        // relative URL is taken from HTTP "Host" header of incoming request
        assertEquals("http://test.com:4567/keycloak", oidcClientConfigurationWithResolvedUrls.getAuthServerBaseUrl());
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

    /**
     * A request whose URI has no scheme component (e.g. a path-only URI as produced by some containers) must not
     * make resolution of a relative auth-server-url throw, even when SSL is required.
     */
    @Test
    public void testUnitRelativeAuthServerUrlWithSchemelessRequestDoesNotThrow() throws Exception {
        OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(
                getOidcConfigurationInputStream(CLIENT_SECRET, "/keycloak", null, "ALL"));
        assertEquals(OidcClientConfiguration.RelativeUrlsUsed.ALWAYS, oidcClientConfiguration.getRelativeUrls());
        OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
        oidcClientContext.resolveUrls(
                oidcClientConfiguration,
                new OidcHttpFacade(new TestingHttpServerRequest(null, new URI("/myTestApp")), oidcClientContext, null)
        );
    }

    /**
     * Test a request whose {@link java.net.URI} has no scheme component through the public
     * {@link HttpServerAuthenticationMechanism#evaluateRequest}, which {@link OidcHttpFacade.Request#isSecure()}
     * parses without checking for a {@code null} result.
     */
    @Test
    public void testUnitSchemelessRequestUriDoesNotThrowDuringLoginRedirect() throws Exception {
        TestingHttpServerRequest delegate = new TestingHttpServerRequest(null, new URI("/" + CLIENT_APP + "/secured"));

        OidcClientConfiguration config = new OidcClientConfiguration();
        config.setClientId(CLIENT_ID);
        config.setPublicKeyLocator(new HardcodedPublicKeyLocator(KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic()));
        config.setProviderUrl("http://" + CLIENT_HOST_NAME + ":8080/realms/myrealm");
        config.setPublicClient(true);
        config.setSSLRequired(Oidc.SSLRequired.EXTERNAL);

        OidcClientContext oidcClientContext = new OidcClientContext(config);
        OidcMechanismFactory factory = new OidcMechanismFactory(oidcClientContext);
        HttpServerAuthenticationMechanism mechanism = factory.createAuthenticationMechanism(
                OIDC_NAME, Collections.emptyMap(), getCallbackHandler());

        mechanism.evaluateRequest(delegate);

        assertEquals(Status.NO_AUTH, delegate.getResult());
    }

    private InputStream getOidcConfigurationInputStream(String clientSecret, String authServerUrl) {
        return getOidcConfigurationInputStream(clientSecret, authServerUrl, null, "EXTERNAL");
    }

    private InputStream getOidcConfigurationInputStream(String clientSecret, String authServerUrl, String providerUrl) {
        return getOidcConfigurationInputStream(clientSecret, authServerUrl, providerUrl, "EXTERNAL");
    }

    private InputStream getOidcConfigurationInputStream(String clientSecret, String authServerUrl, String providerUrl, String sslRequired) {
        String providerEntry = providerUrl != null
                ? ",\n    \"provider-url\" : \"" + providerUrl + "\""
                : "";
        String oidcConfig = "{\n" +
                "    \"" + REALM + "\" : \"" + TEST_REALM + "\",\n" +
                "    \"" + RESOURCE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + AUTH_SERVER_URL + "\" : \"" + authServerUrl + "\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"" + sslRequired + "\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + Oidc.ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + clientSecret + "\"\n" +
                "    }" + providerEntry + "\n" +
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
