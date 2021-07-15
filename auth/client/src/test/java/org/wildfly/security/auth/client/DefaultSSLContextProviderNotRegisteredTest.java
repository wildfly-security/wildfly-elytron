package org.wildfly.security.auth.client;

import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

public class DefaultSSLContextProviderNotRegisteredTest {
    private static final String CONFIG_FILE = "file:./src/test/resources/org/wildfly/security/auth/client/test-wildfly-config-client-default-sslcontext.xml";

    @Test
    public void testDefaultSSLContextIsNotReturnedIfNotConfigured() {
        Provider p = new ClientSSLContextProvider(CONFIG_FILE);
        Security.insertProviderAt(p, 1);
        Assert.assertEquals("ClientSSLContextProvider", Security.getProvider("ClientSSLContextProvider").getName());
        AuthenticationContext.empty().run(() -> {
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
