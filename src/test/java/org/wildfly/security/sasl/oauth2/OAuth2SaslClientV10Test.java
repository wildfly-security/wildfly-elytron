/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.AccessController;
import java.util.Arrays;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.realm.token.TokenSecurityRealm;
import org.wildfly.security.auth.realm.token.validator.JwtValidator;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.source.OAuth2CredentialSource;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.sasl.util.AbstractSaslParticipant;
import org.wildfly.security.sasl.util.SaslMechanismInformation;


/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OAuth2SaslClientV10Test extends BaseTestCase {

    private static final MockWebServer server = new MockWebServer();

    @BeforeClass
    public static void onBefore() throws Exception {
        System.setProperty("wildfly.config.url", OAuth2SaslClientV10Test.class.getResource("wildfly-oauth2-test-config-v1_0.xml").toExternalForm());
        server.setDispatcher(createTokenEndpoint());
        server.start(50831);
    }

    @AfterClass
    public static void onAfter() throws Exception {
        server.shutdown();
    }

    @Test
    public void testWithResourceOwnerCredentialsUsingConfiguration() throws Exception {
        URI serverUri = URI.create("protocol://test1.org");
        SaslClient saslClient = createSaslClientFromConfiguration(serverUri);

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
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
    public void testWithClientCredentialsUsingConfiguration() throws Exception {
        URI serverUri = URI.create("protocol://test2.org");
        SaslClient saslClient = createSaslClientFromConfiguration(serverUri);

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
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
    public void failedWithBearerTokenFromConfiguration() throws Exception {
        SaslClient saslClient = createSaslClientFromConfiguration(URI.create("protocol://test3.org"));

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        message = saslClient.evaluateChallenge(message);

        message = saslServer.evaluateResponse(message);
        assertFalse(saslServer.isComplete());
        assertEquals("{\"status\":\"invalid_token\"}", ByteIterator.ofBytes(message).asUtf8String().base64Decode().asUtf8String().drainToString());
    }

    @Test
    public void failedInvalidClientCredentialsUsingConfiguration() throws Exception {
        URI serverUri = URI.create("protocol://test4.org");
        SaslClient saslClient = createSaslClientFromConfiguration(serverUri);

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        try {
            do {
                message = saslClient.evaluateChallenge(message);
                if (message == null) break;
                message = saslServer.evaluateResponse(message);
            } while (message != null);
            fail("Expected bad response from server");
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(e.getCause().getMessage().contains("ELY05125"));
        }
    }

    @Test
    public void testWithResourceOwnerCredentials() throws Exception {
        URI serverUri = URI.create("protocol://test5.org");
        SaslClient saslClient = createSaslClientFromConfiguration(serverUri);

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
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
    public void testWithBearerTokenFromConfiguration() throws Exception {
        SaslClient saslClient = createSaslClientFromConfiguration(URI.create("protocol://test5.org"));

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
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
    public void failedResourceOwnerCredentialsUsingConfiguration() throws Exception {
        URI serverUri = URI.create("protocol://test6.org");
        AuthenticationContext context = AuthenticationContext.getContextManager().get();
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        AuthenticationConfiguration authenticationConfiguration = contextConfigurationClient.getAuthenticationConfiguration(serverUri, context);
        SaslClient saslClient = contextConfigurationClient.createSaslClient(serverUri, authenticationConfiguration, Arrays.asList(SaslMechanismInformation.Names.OAUTHBEARER));

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        try {
            do {
                message = saslClient.evaluateChallenge(message);
                if (message == null) break;
                message = saslServer.evaluateResponse(message);
            } while (message != null);
            fail("Expected bad response from server");
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(e.getCause().getMessage().contains("ELY09001"));
        }
    }

    @Test
    public void testResourceOwnerCredentialsUsingAPI() throws Exception {
        AuthenticationContext context = AuthenticationContext.empty()
                .with(MatchRule.ALL.matchHost("resourceserver.com"), AuthenticationConfiguration.empty()
                        .useCredentials(OAuth2CredentialSource.builder(new URL("http://localhost:50831/token"))
                                .clientCredentials("elytron-client", "dont_tell_me")
                                .useResourceOwnerPassword("alice", "dont_tell_me")
                                .build())
                        .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism("OAUTHBEARER")));
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        AuthenticationConfiguration configuration = contextConfigurationClient.getAuthenticationConfiguration(URI.create("http://resourceserver.com"), context);
        SaslClient saslClient = contextConfigurationClient.createSaslClient(URI.create("http://resourceserver.com"), configuration, Arrays.asList("OAUTHBEARER"));
        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
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
    public void failedResourceOwnerCredentialsUsingAPI() throws Exception {
        AuthenticationContext context = AuthenticationContext.empty()
                .with(MatchRule.ALL.matchHost("resourceserver.com"), AuthenticationConfiguration.empty()
                        .useCredentials(OAuth2CredentialSource.builder(new URL("http://localhost:50831/token"))
                                .useResourceOwnerPassword("unknown", "dont_tell_me")
                                .clientCredentials("bad", "bad")
                                .build())
                        .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism("OAUTHBEARER")))
                .with(MatchRule.ALL.matchHost("localhost").matchPort(50831).matchPath("/token"), AuthenticationConfiguration.empty()
                        .useName("elytron_client")
                        .usePassword("dont_tell_me"));
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        AuthenticationConfiguration configuration = contextConfigurationClient.getAuthenticationConfiguration(URI.create("http://resourceserver.com"), context);
        SaslClient saslClient = contextConfigurationClient.createSaslClient(URI.create("http://resourceserver.com"), configuration, Arrays.asList("OAUTHBEARER"));
        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        try {
            do {
                message = saslClient.evaluateChallenge(message);
                if (message == null) break;
                message = saslServer.evaluateResponse(message);
            } while (message != null);
            fail("Expected bad response from server");
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(e.getCause().getMessage().contains("ELY05125"));
        }
    }

    @Test
    public void testResourceOwnerCredentialsFromExternalCallback() throws Exception {
        URI serverUri = URI.create("protocol://test7.org");
        AuthenticationContext context = AuthenticationContext.getContextManager().get();
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        AuthenticationConfiguration authenticationConfiguration = contextConfigurationClient.getAuthenticationConfiguration(serverUri, context);
        SaslClient saslClient = contextConfigurationClient.createSaslClient(serverUri, authenticationConfiguration, Arrays.asList(SaslMechanismInformation.Names.OAUTHBEARER));

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();


        AuthenticationContext externalContext = AuthenticationContext.empty().with(MatchRule.ALL.matchHost("localhost"), AuthenticationConfiguration.empty().useCallbackHandler(new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    if (callback instanceof NameCallback) {
                        NameCallback.class.cast(callback).setName("alice");
                    } else if (callback instanceof PasswordCallback) {
                        PasswordCallback.class.cast(callback).setPassword("dont_tell_me".toCharArray());
                    } else {
                        throw new RuntimeException("Unexpected callback");
                    }
                }
            }
        }));

        externalContext.run(() -> {
            try {
                byte[] message = AbstractSaslParticipant.NO_BYTES;

                do {
                    message = saslClient.evaluateChallenge(message);
                    if (message == null) break;
                    message = saslServer.evaluateResponse(message);
                } while (message != null);

                assertTrue(saslServer.isComplete());
                assertTrue(saslClient.isComplete());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    public void failedResourceOwnerCredentialsFromExternalCallback() throws Exception {
        URI serverUri = URI.create("protocol://test7.org");
        AuthenticationContext context = AuthenticationContext.getContextManager().get();
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        AuthenticationConfiguration authenticationConfiguration = contextConfigurationClient.getAuthenticationConfiguration(serverUri, context);
        SaslClient saslClient = contextConfigurationClient.createSaslClient(serverUri, authenticationConfiguration, Arrays.asList(SaslMechanismInformation.Names.OAUTHBEARER));

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();


        AuthenticationContext externalContext = AuthenticationContext.empty().with(MatchRule.ALL.matchHost("localhost"), AuthenticationConfiguration.empty().useCallbackHandler(new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    if (callback instanceof NameCallback) {
                        NameCallback.class.cast(callback).setName("alice");
                    } else if (callback instanceof PasswordCallback) {
                        PasswordCallback.class.cast(callback).setPassword("bad_password".toCharArray());
                    } else {
                        throw new RuntimeException("Unexpected callback");
                    }
                }
            }
        }));

        externalContext.run(() -> {
            byte[] message = AbstractSaslParticipant.NO_BYTES;

            try {
                do {
                    message = saslClient.evaluateChallenge(message);
                    if (message == null) break;
                    message = saslServer.evaluateResponse(message);
                } while (message != null);
                fail("Expected bad response from server");
            } catch (Exception e) {
                e.printStackTrace();
                assertTrue(e.getCause().getMessage().contains("ELY05125"));
            }
        });
    }

    private SecurityRealm createSecurityRealmMock() throws MalformedURLException {
        return TokenSecurityRealm.builder().validator(JwtValidator.builder().build()).principalClaimName("preferred_username").build();
    }

    private static Dispatcher createTokenEndpoint() {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest recordedRequest) throws InterruptedException {
                String body = recordedRequest.getBody().readUtf8();
                boolean resourceOwnerCredentials = body.contains("grant_type=password");
                boolean clientCredentials = body.contains("grant_type=client_credentials");

                if (resourceOwnerCredentials
                        && (body.contains("client_id=elytron-client") && body.contains("client_secret=dont_tell_me"))
                        && (body.contains("username=alice") || body.contains("username=jdoe"))
                        && body.contains("password=dont_tell_me")) {
                    JsonObjectBuilder tokenBuilder = Json.createObjectBuilder();

                    tokenBuilder.add("access_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiYXV0aC5zZXJ2ZXIiLCJhdWQiOiJmb3JfbWUiLCJleHAiOjE3NjA5OTE2MzUsInByZWZlcnJlZF91c2VybmFtZSI6Impkb2UifQ.SoPW41_mOFnKXdkwVG63agWQ2k09dEnEtTBztnxHN64");

                    return new MockResponse().setBody(tokenBuilder.build().toString());
                } else if (clientCredentials
                        && (body.contains("client_id=elytron-client") && body.contains("client_secret=dont_tell_me"))
                        && !body.contains("username=")) {
                    JsonObjectBuilder tokenBuilder = Json.createObjectBuilder();

                    tokenBuilder.add("access_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiYXV0aC5zZXJ2ZXIiLCJhdWQiOiJmb3JfbWUiLCJleHAiOjE3NjA5OTE2MzUsInByZWZlcnJlZF91c2VybmFtZSI6Impkb2UifQ.SoPW41_mOFnKXdkwVG63agWQ2k09dEnEtTBztnxHN64");

                    return new MockResponse().setBody(tokenBuilder.build().toString());
                }

                return new MockResponse().setResponseCode(400);
            }
        };
    }

    private SaslClient createSaslClientFromConfiguration(URI serverUri) throws SaslException {
        AuthenticationContext context = AuthenticationContext.getContextManager().get();
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        AuthenticationConfiguration authenticationConfiguration = contextConfigurationClient.getAuthenticationConfiguration(serverUri, context);
        return contextConfigurationClient.createSaslClient(serverUri, authenticationConfiguration, Arrays.asList(SaslMechanismInformation.Names.OAUTHBEARER));
    }
}
