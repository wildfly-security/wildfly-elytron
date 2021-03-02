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
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Test that default SSLContext provider will be ignored when configuration is looping or no default SSL context is configured
 */
public class DefaultSSLContextProviderDoesNotLoopTest {
    private static final String CONFIG_FILE = "./src/test/resources/org/wildfly/security/auth/client/test-wildfly-config-default-ssl-context-invalid-looping.xml";

    @Test
    public void testDefaultSSLContextProviderDoesNotLoopTestCase() throws GeneralSecurityException, ConfigXMLParseException, IOException {
        Security.insertProviderAt(new WildFlyElytronClientDefaultSSLContextProvider(), 1);
        Assert.assertNotNull(Security.getProvider("WildFlyElytronClientDefaultSSLContextProvider"));
        AuthenticationContext authenticationContext = ElytronXmlParser.parseAuthenticationClientConfiguration(new File(CONFIG_FILE).getCanonicalFile().toURI()).create();
        authenticationContext.run(() -> {
            SSLContext defaultSSLContext = null;
            try {
                defaultSSLContext = SSLContext.getDefault();
            } catch (NoSuchAlgorithmException e) {
                Assert.fail("Default SSL context provider should have been ignored because the configuration loops");
            }
            Assert.assertNotNull(defaultSSLContext);
            Assert.assertNotEquals(WildFlyElytronClientDefaultSSLContextProvider.class.getSimpleName(), defaultSSLContext.getProvider().getName()); // diff provider was used since elytron provider is looping
            Assert.assertNotNull(defaultSSLContext.getSocketFactory());
        });
    }
}
