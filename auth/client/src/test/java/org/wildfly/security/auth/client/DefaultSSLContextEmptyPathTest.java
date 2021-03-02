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
 * Test that default SSLContext provider will throw an exception when configured file path is empty
 */
public class DefaultSSLContextEmptyPathTest {

    @Test(expected = IllegalArgumentException.class)
    public void defaultSSLContextNonexistentConfigFileTest() {
        Security.insertProviderAt(new WildFlyElytronClientDefaultSSLContextProvider(""), 1);
        Assert.assertNotNull(Security.getProvider("WildFlyElytronClientDefaultSSLContextProvider"));
        AuthenticationContext authenticationContext = AuthenticationContext.captureCurrent();
        authenticationContext.run(() -> {
            try {
                SSLContext.getDefault();
            } catch (NoSuchAlgorithmException e) {
                Assert.fail("Obtaining default SSL context from provider with invalid path threw incorrect exception");
            }
        });
    }
}
