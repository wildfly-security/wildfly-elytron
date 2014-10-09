/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.keystore;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.impl.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.UnixMD5CryptPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class PasswordFileKeyStoreTest {

    private static final Provider provider = new WildFlyElytronPasswordProvider();

    @BeforeClass
    public static void register() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void remove() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testGetPut() throws Exception {
        final PasswordFactory passwordFactory = PasswordFactory.getInstance(UnixMD5CryptPassword.ALGORITHM_CRYPT_MD5);
        byte[] b = new byte[16];
        ThreadLocalRandom.current().nextBytes(b);
        final Password password = passwordFactory.generatePassword(new EncryptablePasswordSpec("swordfish".toCharArray(), new HashedPasswordAlgorithmSpec(16, b)));
        KeyStore keyStore = KeyStore.getInstance("PasswordFile");
        keyStore.load(new InputStream() {
            public int read() throws IOException {
                return -1;
            }
        }, null);
        keyStore.setEntry("bob", new PasswordEntry(password), null);
        final KeyStore.Entry entry = keyStore.getEntry("bob", null);
        assertNotNull("Missing entry", entry);
        assertTrue("Wrong entry type", entry instanceof PasswordEntry);
        final Password storedPassword = ((PasswordEntry) entry).getPassword();
        assertNotNull(storedPassword);
        assertSame(password, storedPassword);
    }
}
