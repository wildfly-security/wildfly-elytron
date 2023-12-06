package org.wildfly.security.auth.client;

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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ServiceLoader;
import java.util.function.Supplier;

public class EncryptedExpressionXMLParserTest {

    private static final File CREDSTORE_DIR = new File("./target/credstore");
    private static final String CLIENT_CREDSTORE_FILENAME = "/mycredstore.cs";

    @Test
    public void testEncryptedExpressionConfig() throws Exception {
        URL config = getClass().getResource("test-encrypted-expression-v1_0.xml");
        SecurityFactory<EncryptedExpressionContext> clientConfiguration = EncryptedExpressionsXmlParser.parseEncryptedExpressionClientConfiguration(config.toURI());
        Assert.assertNotNull(clientConfiguration);
    }

    @BeforeClass
    public static void prepareCredStores() throws Exception {
        if (!CREDSTORE_DIR.exists()) {
            CREDSTORE_DIR.mkdirs();
        }

        CredentialStore credentialStore = CredentialStore.getInstance("PropertiesCredentialStore", getProvidersSupplier());
        createCredentialStore(credentialStore, CREDSTORE_DIR, CLIENT_CREDSTORE_FILENAME);
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
        Assert.assertTrue("Credential Store deleted", new File(CREDSTORE_DIR, CLIENT_CREDSTORE_FILENAME).delete());
        Assert.assertTrue("Credential store directory deleted", CREDSTORE_DIR.delete());
    }

    static void createCredentialStore(CredentialStore credentialStore, File credStoreDirectory, String credStoreFilename) throws Exception {
        Map<String, String> credentialStoreAttributes = new HashMap<>();
        credentialStoreAttributes.put("create", Boolean.TRUE.toString());
        credentialStoreAttributes.put("location", credStoreDirectory + credStoreFilename);
        credentialStoreAttributes.put("modifiable", Boolean.TRUE.toString());
        credentialStore.initialize(credentialStoreAttributes);

        final SecretKey secretKey = SecretKeyUtil.generateSecretKey(256);
        credentialStore.store("secretkey1", new SecretKeyCredential(secretKey));
        credentialStore.flush();
    }
}