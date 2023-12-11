package org.wildfly.security.auth.client;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.SecurityFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.security.KeyStore;

public class EncryptedExpressionXMLParserTest {

    private static File CREDSTORE_DIR = new File("./target/credstore");
    private static final String CLIENT_CREDSTORE_FILENAME = "/mycredstore.cs";
    private static final char[] PASSWORD = "password".toCharArray();

    @Test
    public void testEncryptedExpressionConfig() throws Exception {
        URL config = getClass().getResource("test-encrypted-expression-v1_0.xml");
        SecurityFactory<EncryptedExpressionContext> clientConfiguration = EncryptedExpressionsXmlParser.parseEncryptedExpressionClientConfiguration(config.toURI());
        Assert.assertNotNull(clientConfiguration);
    }

    @BeforeClass
    public static void prepareCredStores() throws Exception {
        if (CREDSTORE_DIR.exists() == false) {
            CREDSTORE_DIR.mkdirs();
        }

        KeyStore credentialStore = KeyStore.getInstance("JCEKS");
        credentialStore.load(null, null);

        createCredentialStore(credentialStore);

        File clientFile = new File(CREDSTORE_DIR, CLIENT_CREDSTORE_FILENAME);

        try (FileOutputStream clientStream = new FileOutputStream(clientFile)){
            credentialStore.store(clientStream, PASSWORD);
        }
    }


    @AfterClass
    public static void removeProvider() {
        Assert.assertTrue("Credential Store deleted", new File(CREDSTORE_DIR, CLIENT_CREDSTORE_FILENAME).delete());
        Assert.assertTrue("Credential store directory deleted", CREDSTORE_DIR.delete());
    }
}
