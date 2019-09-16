/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.realm.token.TokenSecurityRealm;
import org.wildfly.security.auth.realm.token.validator.JwtValidator;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.source.oauth2.OAuth2CredentialSource;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.oauth2.OAuth2SaslServerFactory;
import org.wildfly.security.sasl.oauth2.WildFlyElytronSaslOAuth2Provider;
import org.wildfly.security.sasl.plain.PlainSaslServerFactory;
import org.wildfly.security.sasl.plain.WildFlyElytronSaslPlainProvider;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.sasl.util.AbstractSaslParticipant;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * Tests a successful SASL authentication with masked password in client xml configuration
 *
 * @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */

public class MaskedPasswordSaslAuthenticationTest {

    private static final String PLAIN = "PLAIN";
    private static final String USERNAME = "Guest";
    private static final String PASSWORD = "gpwd";
    private static final String CONFIG_FILE = "wildfly-masked-password-sasl-config-v1_4.xml";
    private static final MockWebServer server = new MockWebServer();

    private static final Provider[] providers = new Provider[] {
            WildFlyElytronSaslPlainProvider.getInstance(),
            WildFlyElytronSaslOAuth2Provider.getInstance(),
            WildFlyElytronPasswordProvider.getInstance()
    };

    @BeforeClass
    public static void registerProvider() throws IOException {
        for (Provider provider : providers) {
            Security.insertProviderAt(provider, 1);
        }
        server.setDispatcher(createTokenEndpoint());
        server.start(50831);
        System.setProperty("wildfly.config.url", MaskedPasswordSaslAuthenticationTest.class.getResource(CONFIG_FILE).toExternalForm());
    }

    @AfterClass
    public static void removeProvider() throws IOException {
        for (Provider provider : providers) {
            Security.removeProvider(provider.getName());
        }
        server.shutdown();
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

    /**
     * Test a successful exchange using the PLAIN mechanism where password in client
     * XML config is specified as a masked password.
     */
    @Test
    public void testSuccessfulExchangeWithXmlConfig() throws Exception {
        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                                .setUserName(USERNAME)
                                .setPassword(PASSWORD.toCharArray())
                                .build();

        //Creating SASL client from XML configuration file
        AccessController.doPrivileged((PrivilegedAction<Integer>) () -> Security.insertProviderAt(WildFlyElytronPasswordProvider.getInstance(), 1));
        AuthenticationContext context = AuthenticationContext.getContextManager().get();

        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        SaslClient client = contextConfigurationClient.createSaslClient(new URI(CONFIG_FILE), context.authRules.configuration, Arrays.asList(new String[]{PLAIN}));

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);
        assertEquals("\0"+USERNAME+"\0"+PASSWORD,new String(message, StandardCharsets.UTF_8));

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals(USERNAME, server.getAuthorizationID());
    }

    @Test
    public void testSuccessfulExchangeWithProgrammaticConfig() throws Exception {
        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setUserName(USERNAME)
                .setPassword(PASSWORD.toCharArray())
                .build();

        //Creating SASL client from authentication configuration programmatically
        AuthenticationConfiguration maskedConfig =
                AuthenticationConfiguration.empty()
                        .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism(PLAIN))
                        .useName(USERNAME)
                        .useMaskedPassword("YFBlotObdCo=", null, null, 100, "12345678", null);

        AuthenticationContext context = AuthenticationContext.empty();
        context = context.with(MatchRule.ALL.matchHost("masked"), maskedConfig);
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        SaslClient client = contextConfigurationClient.createSaslClient(URI.create("http://masked/"), context.authRules.configuration, Arrays.asList(PLAIN));

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);
        assertEquals("\0"+USERNAME+"\0"+PASSWORD,new String(message, StandardCharsets.UTF_8));

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals(USERNAME, server.getAuthorizationID());
    }

    /**
     * Test a successful exchange using the OAUTHBEARER mechanism where client credentials secret and resource owner password in
     * XML config are specified as masked passwords.
     */
    @Test
    public void testSuccessfulOAuth2ExchangeWithXmlConfig() throws Exception {
        URI serverUri = URI.create("protocol://oauth2/");
        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        //Creating SASL client from XML configuration file
        AuthenticationContext context = AuthenticationContext.getContextManager().get();
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        AuthenticationConfiguration authenticationConfiguration = contextConfigurationClient.getAuthenticationConfiguration(serverUri, context);
        SaslClient client = contextConfigurationClient.createSaslClient(serverUri, authenticationConfiguration, Arrays.asList(SaslMechanismInformation.Names.OAUTHBEARER));

        assertNotNull("OAuth2SaslClient is null", client);

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        do {
            message = client.evaluateChallenge(message);
            if (message == null) break;
            message = saslServer.evaluateResponse(message);
        } while (message != null);

        assertTrue(saslServer.isComplete());
        assertTrue(client.isComplete());
    }

    /**
     * Test a successful exchange using the OAUTHBEARER mechanism where client credentials secret and resource owner password
     * are specified as masked passwords.
     */
    @Test
    public void testSuccessfulOAuth2ExchangeWithProgrammaticConfig() throws Exception {
        AuthenticationContext context = AuthenticationContext.empty()
                .with(MatchRule.ALL.matchHost("resourceserver.com"), AuthenticationConfiguration.empty()
                        .useCredentials(OAuth2CredentialSource.builder(new URL("http://localhost:50831/token"))
                                .maskedClientCredentials("elytron-client", "FMkAWSbPn9SCEejW71SvLA==", "masked-MD5-DES", "somearbitrarycrazystringthatdoesnotmatter", 100, "12345678", null)
                                .useResourceOwnerMaskedPassword("alice", "FMkAWSbPn9SCEejW71SvLA==", null, null, 100, "12345678", null)
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



    private SecurityRealm createSecurityRealmMock() {
        return TokenSecurityRealm.builder().validator(JwtValidator.builder().build()).principalClaimName("preferred_username").build();
    }
}
