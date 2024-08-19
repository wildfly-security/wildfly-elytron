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
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.encryption.SecretKeyUtil;

import javax.crypto.SecretKey;
import java.io.File;
import java.net.URL;
import java.security.Provider;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.function.Supplier;

/**
 * A test class to test the XML parser for Encrypted Expression Client Schema.
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */

public class EncryptedExpressionXMLParserTest {

    private static final File CREDSTORE_DIR = new File("./target/credstore");
    private static final String CLIENT_CREDSTORE_FILENAME = "/mycredstore.cs";

    @Test
    public void testEncryptedExpressionClient() throws Exception {
        URL config = getClass().getResource("test-encryption-client-v1_0.xml");
        System.setProperty("wildfly.config.url", config.getPath());

        SecurityFactory<EncryptionClientContext> clientConfiguration = EncryptionClientXmlParser.parseEncryptionClientConfiguration(config.toURI());
        Assert.assertNotNull(clientConfiguration);
        System.clearProperty("wildfly.config.url");
    }

    @BeforeClass
    public static void prepareCredStores() throws Exception {
        if (!CREDSTORE_DIR.exists()) {
            CREDSTORE_DIR.mkdirs();
        }

        CredentialStore credentialStore = CredentialStore.getInstance("PropertiesCredentialStore", getProvidersSupplier());
        createCredentialStore(credentialStore, CREDSTORE_DIR, CLIENT_CREDSTORE_FILENAME);

        String credStorePath = CREDSTORE_DIR.getAbsolutePath().replace("/./", "/") + CLIENT_CREDSTORE_FILENAME;
        System.setProperty("CREDSTORE_PATH_PROP", credStorePath);
        Assert.assertEquals(credStorePath, System.getProperty("CREDSTORE_PATH_PROP"));
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
    public static void removeProvider() {
        Assert.assertNotNull(System.clearProperty("CREDSTORE_PATH_PROP"));
        Assert.assertTrue("Credential Store deleted", new File(CREDSTORE_DIR, CLIENT_CREDSTORE_FILENAME).delete());
        Assert.assertTrue("Credential store directory deleted", CREDSTORE_DIR.delete());
    }

    static void createCredentialStore(CredentialStore credentialStore, File credStoreDirectory, String credStoreFilename) throws Exception {
        Map<String, String> credentialStoreAttributes = new HashMap<>();
        credentialStoreAttributes.put("create", Boolean.TRUE.toString());
        credentialStoreAttributes.put("location", credStoreDirectory + credStoreFilename);
        credentialStoreAttributes.put("modifiable", Boolean.TRUE.toString());
        credentialStore.initialize(credentialStoreAttributes);

        // store the first alias to back up the first test resolver
        final SecretKey secretKey = SecretKeyUtil.generateSecretKey(256);
        credentialStore.store("secretkey1", new SecretKeyCredential(secretKey));
        credentialStore.flush();

        // store the second alias to back up the second test resolver
        final SecretKey secretKey2 = SecretKeyUtil.generateSecretKey(256);
        credentialStore.store("secretkey2", new SecretKeyCredential(secretKey2));
        credentialStore.flush();
    }
}