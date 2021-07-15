package org.wildfly.security.auth.client;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.client.config.ConfigXMLParseException;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

public class DefaultSSLContextProviderFromCurrentContextTest {
    private static final String CONFIG_FILE = "file:./src/test/resources/org/wildfly/security/auth/client/test-wildfly-config-client-default-sslcontext.xml";

    @Test
    public void testDefaultSSLContextFromCurrentAuthenticationClientConfiguration() throws GeneralSecurityException, URISyntaxException, ConfigXMLParseException {
        Provider p = new ClientSSLContextProvider();
        Security.insertProviderAt(p, 1);
        Assert.assertEquals("ClientSSLContextProvider", Security.getProvider("ClientSSLContextProvider").getName());
        AuthenticationContext authenticationContext = ElytronXmlParser.parseAuthenticationClientConfiguration(new URI(CONFIG_FILE)).create();
        authenticationContext.run(() -> {
            SSLContext cip = null;
            try {
                cip = SSLContext.getDefault();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                Assert.fail();
            }
            Assert.assertEquals(cip.getProvider().getName(), "ClientSSLContextProvider");
            Assert.assertNotNull(cip);
            Assert.assertNotNull(cip.getSocketFactory());
        });
    }
}
