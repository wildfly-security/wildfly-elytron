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
import org.wildfly.client.config.ConfigXMLParseException;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Test that default SSLContext from provider can use programmatic configuration
 */
public class DefaultSSLContextProviderProgrammaticConfigurationTest {
    private static final String CONFIG_FILE = "file:./src/test/resources/org/wildfly/security/auth/client/test-wildfly-config-client-default-sslcontext.xml";

    @Test
    public void testDefaultSSLContextProgrammaticConfiguration() throws GeneralSecurityException, URISyntaxException, ConfigXMLParseException {
        Security.insertProviderAt(new WildFlyElytronClientDefaultSSLContextProvider(), 1);
        Assert.assertNotNull(Security.getProvider("WildFlyElytronClientDefaultSSLContextProvider"));
        AuthenticationContext authenticationContext = ElytronXmlParser.parseAuthenticationClientConfiguration(new URI(CONFIG_FILE)).create();
        authenticationContext.run(() -> {
            SSLContext defaultSSLContext = null;
            try {
                defaultSSLContext = SSLContext.getDefault();
            } catch (NoSuchAlgorithmException e) {
                Assert.fail("Default SSL context from provider threw an exception when obtaining default SSL context from programmatic configuration ");
            }
            Assert.assertNotNull(defaultSSLContext);
            Assert.assertEquals(WildFlyElytronClientDefaultSSLContextProvider.class.getSimpleName(), defaultSSLContext.getProvider().getName());
            Assert.assertNotNull(defaultSSLContext.getSocketFactory());
            // this will make sure the file is used instead of the empty AuthenticationContext
            Assert.assertEquals(1, defaultSSLContext.createSSLEngine().getSSLParameters().getProtocols().length);
            Assert.assertEquals(1, defaultSSLContext.getSocketFactory().getSupportedCipherSuites().length);
        });
    }
}
