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
 * Test that when no config path passed to provider and there is no configuration present in the code, the provider will be ignored
 */
public class DefaultSSLContextProviderIsIgnoredWhenConfigIsMissingTest {

    @Test
    public void defaultSSLContextProviderIsIgnoredWhenConfigIsMissingTest() {
        Security.insertProviderAt(new WildFlyElytronClientDefaultSSLContextProvider(), 1);
        Assert.assertNotNull(Security.getProvider("WildFlyElytronClientDefaultSSLContextProvider"));
        SSLContext defaultSSLContext = null;
        try {
            defaultSSLContext = SSLContext.getDefault();
        } catch (NoSuchAlgorithmException e) {
            Assert.fail("Default SSL context from provider was not ignored when no configuration was present");
        }
        Assert.assertNotNull(defaultSSLContext);
        Assert.assertNotEquals(WildFlyElytronClientDefaultSSLContextProvider.class.getSimpleName(), defaultSSLContext.getProvider().getName()); // different provider was used since no default SSL context configured in Elytron client
        Assert.assertNotNull(defaultSSLContext.getSocketFactory());
    }
}
