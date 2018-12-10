/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.oauth2;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.realm.token.TokenSecurityRealm;
import org.wildfly.security.auth.realm.token.validator.OAuth2IntrospectValidator;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.mechanism.oauth2.OAuth2Server;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.sasl.util.AbstractSaslParticipant;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@RunWith(JMockit.class)
public class OAuth2SaslTest extends BaseTestCase {

    @Test
    public void testQueryMechanisms() {
        SaslServerFactory serverFactory = obtainSaslServerFactory(OAuth2SaslServerFactory.class);
        String[] mechanismNames = serverFactory.getMechanismNames(Collections.emptyMap());

        assertEquals(1, mechanismNames.length);
        assertEquals("OAUTHBEARER", mechanismNames[0]);
    }

    /**
     * Tests the abstract message flow, accordingly with the RFC-7628. Here, the steps that interact with the OAuth2 Authorization Server
     * are omitted and an access token is passed directly to the OAuth2 SASL Server.
     *
     * @throws Exception
     */
    @Test
    public void testAbstractMessageFlow() throws Exception {
        SaslClientFactory saslClientFactory = obtainSaslClientFactory(OAuth2SaslClientFactory.class);

        assertNotNull("OAuth2SaslClientFactory not found", saslClientFactory);

        SaslClient saslClient = saslClientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OAUTHBEARER}, "user", "imap", "resourceserver.com", Collections.emptyMap(), new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    if (callback instanceof CredentialCallback) {
                        CredentialCallback credentialCallback = (CredentialCallback) callback;
                        JsonObjectBuilder tokenBuilder = Json.createObjectBuilder();

                        tokenBuilder.add("active", true);
                        tokenBuilder.add("username", "elytron@jboss.org");

                        credentialCallback.setCredential(new BearerTokenCredential(tokenBuilder.build().toString()));
                    }
                }
            }
        });

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.com")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        do {
            message = saslClient.evaluateChallenge(message);
            if (message == null) break;
            message = saslServer.evaluateResponse(message);
        } while (message != null);

        assertTrue(saslServer.isComplete());
        assertTrue(saslClient.isComplete());
    }

    @Test
    public void testSuccessfulWithoutAuthorizationId() throws Exception {
        SaslClientFactory saslClientFactory = obtainSaslClientFactory(OAuth2SaslClientFactory.class);

        assertNotNull("OAuth2SaslClientFactory not found", saslClientFactory);

        SaslClient saslClient = saslClientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OAUTHBEARER}, null, "imap", "resourceserver.com", Collections.emptyMap(), new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    if (callback instanceof CredentialCallback) {
                        CredentialCallback credentialCallback = (CredentialCallback) callback;
                        JsonObjectBuilder tokenBuilder = Json.createObjectBuilder();

                        tokenBuilder.add("active", true);
                        tokenBuilder.add("username", "elytron@jboss.org");

                        credentialCallback.setCredential(new BearerTokenCredential(tokenBuilder.build().toString()));
                    }
                }
            }
        });

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.com")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        do {
            message = saslClient.evaluateChallenge(message);
            if (message == null) break;
            message = saslServer.evaluateResponse(message);
        } while (message != null);

        assertTrue(saslServer.isComplete());
        assertTrue(saslClient.isComplete());
    }

    /**
     * Tests error messages from server, usually after an usuccessful authentication. Where in this case, the server must
     * return a JSON with details about what it failed.
     *
     * @throws Exception
     */
    @Test
    public void testFailedAuthenticationFlow() throws Exception {
        SaslClientFactory saslClientFactory = obtainSaslClientFactory(OAuth2SaslClientFactory.class);

        assertNotNull("OAuth2SaslClientFactory not found", saslClientFactory);

        SaslClient saslClient = saslClientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OAUTHBEARER}, "user", "imap", "resourceserver.com", Collections.emptyMap(), new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    if (callback instanceof CredentialCallback) {
                        CredentialCallback credentialCallback = (CredentialCallback) callback;
                        JsonObjectBuilder tokenBuilder = Json.createObjectBuilder();

                        tokenBuilder.add("active", false);

                        credentialCallback.setCredential(new BearerTokenCredential(tokenBuilder.build().toString()));
                    }
                }
            }
        });

        assertNotNull("OAuth2SaslClient is null", saslClient);

        HashMap<String, Object> saslServerConfig = new HashMap<>();

        saslServerConfig.put(OAuth2Server.CONFIG_OPENID_CONFIGURATION_URL, "http://as.test.org/oauth2/.well-known/openid-configuration");

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.com")
                .setProperties(saslServerConfig)
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;
        byte[] serverErrorMessage;

        assertNotNull(message = saslClient.evaluateChallenge(message)); // 1. Client sends an invalid initial client response.
        assertNotNull(serverErrorMessage = message = saslServer.evaluateResponse(message)); // 2. Server responds with an error message.
        assertNotNull(message = saslClient.evaluateChallenge(message)); // 3. Client sends a dummy client response.
        try {
            saslServer.evaluateResponse(message); // 4. Server fails the authentication.
            fail("Expected SaslException not thrown");
        } catch (SaslException ignore) {}

        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());
        assertEquals("{\"status\":\"invalid_token\",\"openid-configuration\":\"http://as.test.org/oauth2/.well-known/openid-configuration\"}", new String(CodePointIterator.ofUtf8Bytes(serverErrorMessage).base64Decode().drain()));
    }

    private SecurityRealm createSecurityRealmMock() throws MalformedURLException {
        configureReplayTokenIntrospectionEndpoint();
        return TokenSecurityRealm.builder().validator(OAuth2IntrospectValidator.builder()
                .clientId("wildfly-elytron")
                .clientSecret("dont_tell_me")
                .tokenIntrospectionUrl(new URL("http://as.test.org/oauth2/token/introspect")).build()).build();
    }

    private void configureReplayTokenIntrospectionEndpoint() {
        final Class<?> classToMock;
        try {
            classToMock = Class.forName("org.wildfly.security.auth.realm.token.validator.OAuth2IntrospectValidator", true, TokenSecurityRealm.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new NoClassDefFoundError(e.getMessage());
        }
        new MockUp<Object>(classToMock){
            @Mock
            public JsonObject introspectAccessToken(URL tokenIntrospectionUrl, String clientId, String clientSecret, String token, SSLContext sslContext, HostnameVerifier hostnameVerifier) throws IOException {
                return Json.createReader(new ByteArrayInputStream(token.getBytes())).readObject();
            }
        };
    }
}
