/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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

import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Test that configuration file passed to Elytron client provider has precedence over programmatic configuration
 */
public class DefaultSSLContextFromFileWorksAndHasPrecedenceTest {
    private static final String CONFIG_FILE = "./src/test/resources/org/wildfly/security/auth/client/test-wildfly-config-client-default-sslcontext.xml";

    @Test
    public void testDefaultSSLContextFromFileWorksAndHasPrecedence() {
        Security.insertProviderAt(new WildFlyElytronClientDefaultSSLContextProvider(CONFIG_FILE), 1);
        Assert.assertNotNull(Security.getProvider("WildFlyElytronClientDefaultSSLContextProvider"));
        AuthenticationContext.empty().run(() -> {    // This will be ignored because file passed to provider has precedence
            SSLContext defaultSSLContext = null;
            try {
                defaultSSLContext = SSLContext.getDefault();
            } catch (NoSuchAlgorithmException e) {
                Assert.fail("Obtaining of default SSLContext with both config file and programmatic configuration present threw NoSuchAlgorithmException exception.");
            }
            Assert.assertNotNull(defaultSSLContext);
            Assert.assertNotNull(defaultSSLContext.getSocketFactory());
            // if programmatic configuration was used, it would not find the default SSLContext configured and the provider would be ignored
            // because the file was used, the default SSL context was present and returned with SSLContext.getDefault() call
            Assert.assertEquals(WildFlyElytronClientDefaultSSLContextProvider.class.getSimpleName(), defaultSSLContext.getProvider().getName());
            Assert.assertEquals(defaultSSLContext.createSSLEngine().getSSLParameters().getProtocols().length, 1);
            Assert.assertEquals(defaultSSLContext.getSocketFactory().getSupportedCipherSuites().length, 1);
        });
    }
}
