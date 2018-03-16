package org.wildfly.security.auth.client;

import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.security.SecurityFactory;

/**
 * @author Tomas Hofman (thofman@redhat.com)
 */
public class ElytronXmlParserTest {

    private static File KEYSTORE_DIR = new File("./target/keystore");
    private static final String CLIENT_KEYSTORE_FILENAME = "/client.keystore";


    /**
     * ELY-1428
     */
    @Test
    public void testKeyStoreClearPassword() throws ConfigXMLParseException, URISyntaxException {
        URL config = getClass().getResource("test-wildfly-config.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
    }

    @BeforeClass
    public static void prepareKeyStores() throws IOException {
        if (KEYSTORE_DIR.exists() == false) {
            KEYSTORE_DIR.mkdirs();
        }

        copyKeyStore(CLIENT_KEYSTORE_FILENAME);
    }

    private static File copyKeyStore(String keyStoreFileName) throws IOException {
        File keyStore = new File(KEYSTORE_DIR, keyStoreFileName);
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(keyStore);
            IOUtils.copy(ElytronXmlParserTest.class.getResourceAsStream(keyStoreFileName), fos);
        } finally {
            safeClose(fos);
        }
        return keyStore;
    }

    private static void safeClose(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable ignored) {}
        }
    }

}
