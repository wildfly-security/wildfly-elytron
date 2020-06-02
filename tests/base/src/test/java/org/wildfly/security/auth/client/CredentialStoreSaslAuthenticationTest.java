/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.credential.store.CredentialStoreBuilder;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.sasl.plain.PlainSaslServerFactory;
import org.wildfly.security.sasl.plain.WildFlyElytronSaslPlainProvider;
import org.wildfly.security.sasl.test.SaslServerBuilder;

/**
 * Tests a successful SASL authentication with a credential store reference in xml configuration
 *
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */

public class CredentialStoreSaslAuthenticationTest {

    private static final String PLAIN = "PLAIN";
    private static final String USERNAME = "Guest";
    private static final String PASSWORD = "gpwd";
    private static final String CREDENTIAL_CONFIG_FILE = "wildfly-credential-sasl-config.xml";
    private static String BASE_STORE_DIRECTORY = "target/ks-cred-stores";

    private static final Provider[] providers = new Provider[] {
            WildFlyElytronSaslPlainProvider.getInstance(),
            WildFlyElytronPasswordProvider.getInstance()
    };

    @BeforeClass
    public static void setUp() throws Exception {
        System.setProperty("wildfly.config.url", CredentialStoreSaslAuthenticationTest.class.getResource(CREDENTIAL_CONFIG_FILE).toExternalForm());

        // Enable Elytron Password provider manually to configure credential store
        Security.insertProviderAt(providers[1], 1);

        CredentialStoreBuilder.get().setKeyStoreFile(BASE_STORE_DIRECTORY + "/mycredstore.cs")
                .setKeyStoreType("JCEKS")
                .setKeyStorePassword("StorePassword")
                .addPassword(USERNAME, PASSWORD)
                .build();

        // disable Elytron provider before client and server exchange messages
        Security.removeProvider(providers[1].getName());
    }

    @AfterClass
    public static void tearDown() throws Exception {
        cleanCredentialStore();
    }

    private static void cleanCredentialStore() {
        File file = new File(BASE_STORE_DIRECTORY + "/mycredstore.cs");
        file.delete();
    }

    @Test
    public void testSuccessfulSaslAuthenticationWithCredentialStore() throws Exception {

            SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                    .setProviderSupplier(() -> providers)
                    .setUserName(USERNAME)
                    .setPassword(PASSWORD.toCharArray())
                    .build();

            // Create SASL client from XML configuration file
            AuthenticationContext context = AuthenticationContext.getContextManager().get();

            AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
            SaslClient client = contextConfigurationClient.createSaslClient(new URI(CREDENTIAL_CONFIG_FILE), context.authRules.getConfiguration(), Arrays.asList(new String[]{PLAIN}));

            assertTrue(client.hasInitialResponse());
            byte[] message = client.evaluateChallenge(new byte[0]);
            assertEquals("\0"+USERNAME+"\0"+PASSWORD,new String(message, StandardCharsets.UTF_8));

            server.evaluateResponse(message);
            assertTrue(server.isComplete());
            assertTrue(client.isComplete());
            assertEquals(USERNAME, server.getAuthorizationID());

    }

}
