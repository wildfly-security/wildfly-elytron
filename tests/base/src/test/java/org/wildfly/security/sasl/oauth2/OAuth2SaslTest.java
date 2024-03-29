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

import static org.wildfly.security.sasl.test.SaslTestUtil.obtainSaslClientFactory;
import static org.wildfly.security.sasl.test.SaslTestUtil.obtainSaslServerFactory;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.AggregateSecurityRealm;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.realm.token.TokenSecurityRealm;
import org.wildfly.security.auth.realm.token.validator.OAuth2IntrospectValidator;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.util.RegexNameRewriter;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.mechanism.oauth2.OAuth2Server;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.sasl.util.AbstractSaslParticipant;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
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
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.Permissions;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
// has dependency on wildfly-elytron-realm-auth-token
@RunWith(JMockit.class)
public class OAuth2SaslTest {

    private static final Provider provider = WildFlyElytronSaslOAuth2Provider.getInstance();

    @BeforeClass
    public static void registerProvider() {
        Security.insertProviderAt(provider, 1);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

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

    @Test
    public void testSuccessfulAuthorizationWithAggregateRealmWithoutPrincipalTransformer() throws Exception {
        testSuccessfulAuthorizationWithAggregateRealm(false);
    }

    @Test
    public void testSuccessfulAuthorizationWithAggregateRealmWithPrincipalTransformer() throws Exception {
        testSuccessfulAuthorizationWithAggregateRealm(true);
    }

    private void testSuccessfulAuthorizationWithAggregateRealm(boolean usePrincipalTransformer) throws Exception {
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

        Permissions permissions = new Permissions();
        permissions.add(new LoginPermission());
        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.com")
                .setProtocol("imap")
                .addRealm("oauth-realm", createAggregateSecurityRealmMock(usePrincipalTransformer))
                .setDefaultRealmName("oauth-realm")
                .setPermissionsMap(Collections.singletonMap("admin", permissions))
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

    private SecurityRealm createAggregateSecurityRealmMock(boolean usePrincipalTransformer) throws Exception {
        configureReplayTokenIntrospectionEndpoint();
        SecurityRealm authenticationRealm =  TokenSecurityRealm.builder().validator(OAuth2IntrospectValidator.builder()
                .clientId("wildfly-elytron")
                .clientSecret("dont_tell_me")
                .tokenIntrospectionUrl(new URL("http://as.test.org/oauth2/token/introspect")).build()).build();


        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 1);
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal(usePrincipalTransformer ? "elytron" : "elytron@jboss.org"));
        newIdentity.create();
        MapAttributes newAttributes = new MapAttributes();
        newAttributes.addAll("roles", Arrays.asList("admin"));
        newIdentity.setAttributes(newAttributes);
        newIdentity.dispose();
        SecurityRealm authorizationRealm = new FileSystemSecurityRealm(getRootPath(false), 1);
        return usePrincipalTransformer ? new AggregateSecurityRealm(authenticationRealm, new RegexNameRewriter(Pattern.compile("(.*)@jboss\\.org"), "$1", true).asPrincipalRewriter(), authorizationRealm)
                : new AggregateSecurityRealm(authenticationRealm, authorizationRealm);
    }

    private Path getRootPath(boolean deleteIfExists) throws Exception {
        Path rootPath = Paths.get(getClass().getResource(File.separator).toURI())
                .resolve("filesystem-realm");

        if (rootPath.toFile().exists() && !deleteIfExists) {
            return rootPath;
        }

        return Files.walkFileTree(Files.createDirectories(rootPath), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private Path getRootPath() throws Exception {
        return getRootPath(true);
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
