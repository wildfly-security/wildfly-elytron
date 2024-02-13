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

import okhttp3.mockwebserver.MockWebServer;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.encryption.SecretKeyUtil;
import org.wildfly.security.encryption.client.EncryptionClientContext;
import org.wildfly.security.encryption.client.EncryptedExpressionResolutionException;
import org.wildfly.security.encryption.client.EncryptionClientXmlParser;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.sasl.oauth2.WildFlyElytronSaslOAuth2Provider;
import org.wildfly.security.sasl.plain.PlainSaslServerFactory;
import org.wildfly.security.sasl.plain.WildFlyElytronSaslPlainProvider;
import org.wildfly.security.sasl.test.SaslServerBuilder;

import javax.crypto.SecretKey;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.function.Supplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.auth.client.MaskedPasswordSaslAuthenticationTest.createTokenEndpoint;

/**
 * Tests a successful SASL authentication with encrypted expression in client xml configuration
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */

public class EncryptionClientSaslAuthenticationTest {
    private static final File CREDSTORE_DIR = new File("./target/credstore");
    private static final String CONFIG_FILE = "wildfly-encryption-client-ssl-config-v1_7.xml";
    private static final String CRED_STORE_FILE = "mycredstore.cs";
    private static final String DEFAULT_RESOLVER = "my-resolver";
    private static final String PLAIN = "PLAIN";
    private static final String USERNAME = "Guest";
    private static final String PASSWORD = "gpwd";
    private static final String SECRET_KEY_ALIAS = "secretkey";

    private static final MockWebServer server = new MockWebServer();

    private static final Provider[] providers = new Provider[] {
            WildFlyElytronSaslPlainProvider.getInstance(),
            WildFlyElytronSaslOAuth2Provider.getInstance(),
            WildFlyElytronPasswordProvider.getInstance()
    };

    @BeforeClass
    public static void setup() throws GeneralSecurityException, IOException {
        for (Provider provider : providers) {
            Security.insertProviderAt(provider, 1);
        }

        if (!CREDSTORE_DIR.exists()) {
            CREDSTORE_DIR.mkdirs();
        }

        CredentialStore credentialStore = CredentialStore.getInstance("PropertiesCredentialStore", getProvidersSupplier());
        createCredentialStore(credentialStore);
        String credStorePath = CREDSTORE_DIR.getAbsolutePath().replace("/./", "/") + CRED_STORE_FILE;

        server.setDispatcher(createTokenEndpoint());
        server.start(50831);
        System.setProperty("CREDSTORE_PATH_PROP", credStorePath);
    }

    static void createCredentialStore(CredentialStore credentialStore) throws GeneralSecurityException {
        Map<String, String> credentialStoreAttributes = new HashMap<>();
        credentialStoreAttributes.put("create", Boolean.TRUE.toString());
        credentialStoreAttributes.put("location", CREDSTORE_DIR + CRED_STORE_FILE);
        credentialStoreAttributes.put("modifiable", Boolean.TRUE.toString());
        credentialStore.initialize(credentialStoreAttributes);

        // store the first alias to back up the first test resolver
        final SecretKey secretKey = SecretKeyUtil.generateSecretKey(256);
        credentialStore.store(SECRET_KEY_ALIAS, new SecretKeyCredential(secretKey));
        credentialStore.flush();
    }

    public static Supplier<Provider[]> getProvidersSupplier() {
        return () -> {
            ServiceLoader<Provider> providerLoader = ServiceLoader.load(Provider.class);
            Iterator<Provider> providerIterator = providerLoader.iterator();
            List<Provider> providers = new ArrayList<>();
            while (providerIterator.hasNext()) {
                Provider provider = providerIterator.next();
                if (provider.getName().equals("WildFlyElytron")) continue;
                providers.add(provider);
            }
            return providers.toArray(new Provider[providers.size()]);
        };
    }

    @AfterClass
    public static void removeProvider() throws IOException {
        for (Provider provider : providers) {
            Security.removeProvider(provider.getName());
        }
        server.shutdown();
        System.clearProperty("wildfly.config.url");
        System.clearProperty("CREDSTORE_PATH_PROP");
    }

    @Test
    public void testSuccessfulAuthWithXmlConfig() throws Exception {
        URL config = getClass().getResource(CONFIG_FILE);
        System.setProperty("wildfly.config.url", config.getPath());
        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setUserName(USERNAME)
                .setPassword(PASSWORD.toCharArray())
                .build();

        //Preparing the encrypted expression as a system property
        SecurityFactory<EncryptionClientContext> clientConfiguration = EncryptionClientXmlParser.parseEncryptionClientConfiguration(config.toURI());
        EncryptionClientContext encContext = clientConfiguration.create();
        EncryptionClientContext.getContextManager().setThreadDefault(encContext);
        String encryptedExpression = encContext.getEncryptedExpressionResolver().createExpression(DEFAULT_RESOLVER, PASSWORD, encContext.getEncryptionClientConfiguration());
        System.setProperty("ENC_EXP_PROP", encryptedExpression);

        //Creating SASL client from XML configuration file
        AccessController.doPrivileged((PrivilegedAction<Integer>) () -> Security.insertProviderAt(WildFlyElytronPasswordProvider.getInstance(), 1));
        AuthenticationContext authContext = AuthenticationContext.getContextManager().get();

        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        SaslClient client = contextConfigurationClient.createSaslClient(new URI(CONFIG_FILE), authContext.authRules.configuration, Arrays.asList(new String[]{PLAIN}));

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);
        assertEquals("\0"+USERNAME+"\0"+PASSWORD,new String(message, StandardCharsets.UTF_8));

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals(USERNAME, server.getAuthorizationID());
        System.clearProperty("ENC_EXP_PROP");
    }

    @Test
    public void testUnableToDecryptWithAuthClient() throws Exception {
        URL config = getClass().getResource("test-invalid-token-encryption-client-auth-client-v1_7.xml");
        System.setProperty("wildfly.config.url", config.getPath());
        try {
            SecurityFactory<EncryptionClientContext> clientConfiguration = EncryptionClientXmlParser.parseEncryptionClientConfiguration(config.toURI());
            EncryptionClientContext.getContextManager().setThreadDefault(clientConfiguration.create());
            SecurityFactory<AuthenticationContext> authClientConfiguration = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        } catch (EncryptedExpressionResolutionException e) {
            Assert.assertTrue(e.getMessage().contains("Unable to decrypt expression"));
            System.clearProperty("wildfly.config.url");
        }
    }

    //    @Test
//    public void testSuccessfulExchangeWithProgrammaticConfig() throws Exception {
//        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
//                .setUserName(USERNAME)
//                .setPassword(PASSWORD.toCharArray())
//                .build();
//
//        CredentialStore credentialStore = CredentialStore.getInstance("PropertiesCredentialStore", getProvidersSupplier());
//        createCredentialStore(credentialStore);
//
//        Map<String, EncryptedExpressionResolver.ResolverConfiguration> resolverConfigurationMap = new HashMap<>();
//        resolverConfigurationMap.put(DEFAULT_RESOLVER, new EncryptedExpressionResolver.ResolverConfiguration(DEFAULT_RESOLVER, "myCredentialStore", SECRET_KEY_ALIAS));
//
//        EncryptedExpressionResolver resolver = new EncryptedExpressionResolver()
//                .setResolverConfigurations(resolverConfigurationMap)
//                .setDefaultResolver(DEFAULT_RESOLVER)
//                .setPrefix("ENC");
//
//        //Preparing the encrypted expression config
//        EncryptionClientConfiguration encConfig =
//                EncryptionClientConfiguration.empty()
//                        .addCredentialStore("myCredentialStore", credentialStore)
//                        .addEncryptedExpressionResolver(resolver);
//
//        //Creating SASL client from authentication configuration programmatically
//        AuthenticationConfiguration authWithEncConfig =
//                AuthenticationConfiguration.empty()
//                        .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism(PLAIN))
//                        .useName(USERNAME)
//                        .decryptAndUsePassword(resolver.createExpression(DEFAULT_RESOLVER, PASSWORD, encConfig));
//
//        AuthenticationContext context = AuthenticationContext.empty();
//        context = context.with(MatchRule.ALL.matchHost("masked"), authWithEncConfig);
//        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
//        SaslClient client = contextConfigurationClient.createSaslClient(URI.create("http://masked/"), context.authRules.configuration, Arrays.asList(PLAIN));
//
//        assertTrue(client.hasInitialResponse());
//        byte[] message = client.evaluateChallenge(new byte[0]);
//        assertEquals("\0"+USERNAME+"\0"+PASSWORD,new String(message, StandardCharsets.UTF_8));
//
//        server.evaluateResponse(message);
//        assertTrue(server.isComplete());
//        assertTrue(client.isComplete());
//        assertEquals(USERNAME, server.getAuthorizationID());
//    }

}
