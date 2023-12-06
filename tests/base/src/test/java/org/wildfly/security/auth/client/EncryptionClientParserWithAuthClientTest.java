package org.wildfly.security.auth.client;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.encryption.SecretKeyUtil;
import org.wildfly.security.encryption.client.EncryptedExpressionResolutionException;
import org.wildfly.security.encryption.client.EncryptionClientContext;
import org.wildfly.security.encryption.client.EncryptionClientXmlParser;

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

public class EncryptionClientParserWithAuthClientTest {

    private static final File CREDSTORE_DIR = new File("./target/credstore");
    private static final String CLIENT_CREDSTORE_FILENAME = "/mycredstore.cs";
    private static final String PASSWORD = "password";

    @Test
    public void testEncryptedExpressionWithAuthClient() throws Exception {
        URL config = getClass().getResource("test-auth-client-encryption-client-v1_7.xml");
        System.setProperty("wildfly.config.url", config.getPath());

        SecurityFactory<EncryptionClientContext> clientConfiguration = EncryptionClientXmlParser.parseEncryptionClientConfiguration(config.toURI());
        EncryptionClientContext ctx = clientConfiguration.create();
        EncryptionClientContext.getContextManager().setThreadDefault(ctx);

        String encryptedExpression = ctx.getEncryptedExpressionResolver().createExpression(PASSWORD, ctx.getEncryptionClientConfiguration());
        Assert.assertEquals(PASSWORD, ctx.getEncryptedExpressionResolver().resolveExpression(encryptedExpression, ctx.getEncryptionClientConfiguration()));

        //expression is encrypted during runtime, so it cannot be statically defined in client config file
        System.setProperty("ENC_EXP_PROP", encryptedExpression);
        SecurityFactory<AuthenticationContext> authClientConfiguration = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());

        Assert.assertNotNull(clientConfiguration);
        Assert.assertNotNull(authClientConfiguration);

        System.clearProperty("wildfly.config.url");
        System.clearProperty("ENC_EXP_PROP");
    }


    @Test
    public void testEncryptedExpressionWithoutEncryptionClient() throws Exception {
        URL config = getClass().getResource("test-invalid-encryption-config-auth-client-v1_7.xml");
        try {
            SecurityFactory<EncryptionClientContext> clientConfiguration = EncryptionClientXmlParser.parseEncryptionClientConfiguration(config.toURI());
            EncryptionClientContext.getContextManager().setThreadDefault(clientConfiguration.create());
            SecurityFactory<AuthenticationContext> authClientConfiguration = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        } catch (EncryptedExpressionResolutionException e) {
            Assert.assertTrue(e.getMessage().contains("Encryption client configuration could not be found."));
        }
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
