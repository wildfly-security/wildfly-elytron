/*
 * Copyright 2024 JBoss by Red Hat.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.encryption.client;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.credential.store.CredentialStore;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import static org.wildfly.security.encryption.client.EncryptedExpressionXMLParserTest.createCredentialStore;
import static org.wildfly.security.encryption.client.EncryptedExpressionXMLParserTest.getProvidersSupplier;

/**
 * A test class to tests for functionalities within the {@link EncryptionClientConfiguration} and the
 * {@link EncryptionClientContext} classes.
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */
public class EncryptionClientContextTest {
    private static final File CRED_STORE_DIR = new File("./target/testcredstore");
    private static final String TEST_CRED_STORE_FILENAME_1 = "/testcredstore1.cs";
    private static final String TEST_CRED_STORE_FILENAME_2 = "/testcredstore2.cs";
    private static final String TEST_CRED_STORE_1_NAME = "testcredstore1";
    private static final String TEST_CRED_STORE_2_NAME = "testcredstore2";
    private static final String TEST_RESOLVER_1_NAME = "testresolver1";
    private static final String TEST_RESOLVER_2_NAME = "testresolver2";
    private final EncryptionClientConfiguration config1
            = EncryptionClientConfiguration.empty();

    public static CredentialStore credentialStore1;
    public static CredentialStore credentialStore2;

    @BeforeClass
    public static void prepareCredStores() throws Exception {
        if (!CRED_STORE_DIR.exists()) {
            CRED_STORE_DIR.mkdirs();
        }

        credentialStore1 = CredentialStore.getInstance("PropertiesCredentialStore", getProvidersSupplier());
        credentialStore2 = CredentialStore.getInstance("PropertiesCredentialStore", getProvidersSupplier());
        createCredentialStore(credentialStore1, CRED_STORE_DIR, TEST_CRED_STORE_FILENAME_1);
        createCredentialStore(credentialStore2, CRED_STORE_DIR, TEST_CRED_STORE_FILENAME_2);
    }

    @AfterClass
    public static void deleteCredStores() {
        Assert.assertTrue("Test credential Store 1 deleted", new File(CRED_STORE_DIR, TEST_CRED_STORE_FILENAME_1).delete());
        Assert.assertTrue("Test credential Store 2 deleted", new File(CRED_STORE_DIR, TEST_CRED_STORE_FILENAME_2).delete());
        Assert.assertTrue("Credential store directory deleted", CRED_STORE_DIR.delete());
    }

    @Test
    public void addCredentialStore() {
        EncryptionClientContext ctx = EncryptionClientContext.empty().with(TEST_CRED_STORE_1_NAME, credentialStore1, config1);
        Assert.assertNotNull(ctx.encryptionClientConfiguration.credentialStoreMap.get(TEST_CRED_STORE_1_NAME));
    }

    @Test
    public void removeCredentialStore() {
        EncryptionClientContext ctx = EncryptionClientContext.empty().with(TEST_CRED_STORE_1_NAME, credentialStore1, config1);
        ctx = EncryptionClientContext.empty().withOut(TEST_CRED_STORE_1_NAME, ctx.encryptionClientConfiguration);
        Assert.assertNull(ctx.encryptionClientConfiguration.credentialStoreMap.get(TEST_CRED_STORE_1_NAME));
    }

    @Test
    public void setCredentialStoreMap() {
        Map<String, CredentialStore> credentialStoreMap = new HashMap<>();
        credentialStoreMap.put(TEST_CRED_STORE_1_NAME, credentialStore1);
        credentialStoreMap.put(TEST_CRED_STORE_2_NAME, credentialStore2);
        EncryptionClientContext ctx = EncryptionClientContext.empty().with(credentialStoreMap, config1);
        Assert.assertNotNull(ctx.encryptionClientConfiguration.credentialStoreMap);
        Assert.assertNotNull(ctx.encryptionClientConfiguration.credentialStoreMap.get(TEST_CRED_STORE_1_NAME));
        Assert.assertNotNull(ctx.encryptionClientConfiguration.credentialStoreMap.get(TEST_CRED_STORE_2_NAME));
    }

    @Test
    public void setResolverAndTestEncryptionAndDecryption() {
        EncryptionClientContext ctx = EncryptionClientContext.empty().with(TEST_CRED_STORE_1_NAME, credentialStore1, config1);
        EncryptionClientConfiguration config = ctx.encryptionClientConfiguration;
        EncryptedExpressionResolver resolver = new EncryptedExpressionResolver();
        Map<String, EncryptedExpressionResolver.ResolverConfiguration> resolverConfigurationMap = new HashMap<>();
        resolverConfigurationMap.put(TEST_RESOLVER_1_NAME, new EncryptedExpressionResolver.ResolverConfiguration(TEST_RESOLVER_1_NAME, TEST_CRED_STORE_1_NAME, "secretkey1"));
        resolverConfigurationMap.put(TEST_RESOLVER_2_NAME, new EncryptedExpressionResolver.ResolverConfiguration(TEST_RESOLVER_2_NAME, TEST_CRED_STORE_2_NAME, "secretkey1"));
        resolver.setResolverConfigurations(resolverConfigurationMap);
        resolver.setPrefix("ENC")
                .setResolverConfigurations(resolverConfigurationMap)
                .setDefaultResolver(TEST_RESOLVER_1_NAME);
        ctx = ctx.with(resolver, config);
        Assert.assertEquals(resolver, ctx.encryptionClientConfiguration.encryptedExpressionResolver);
        Assert.assertEquals(resolverConfigurationMap, ctx.encryptionClientConfiguration.encryptedExpressionResolver.getResolverConfiguration());

        String clearText = "password";
        String encryptedExpression = ctx.encryptionClientConfiguration.encryptedExpressionResolver.createExpression(TEST_RESOLVER_1_NAME, clearText, ctx.encryptionClientConfiguration);
        String decryptedExpression = ctx.encryptionClientConfiguration.encryptedExpressionResolver.resolveExpression(encryptedExpression, ctx.encryptionClientConfiguration);
        Assert.assertEquals(clearText, decryptedExpression);
    }
}

