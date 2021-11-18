/*
 * Copyright 2021 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.credential.store.impl;

import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.interfaces.ClearPassword;

import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class MapCredentialStoreTest {

    private static final String KEY = "key";

    private char[] secretPassword;

    private PasswordCredential storedPasswordCredential;

    @Before
    public void prepareEnvironment() {
        secretPassword = "password".toCharArray();
        storedPasswordCredential = new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, secretPassword));
    }

    @Test
    public void testSingleEntryStore() throws Exception {
        final MapCredentialStore mapCredentialStore = new MapCredentialStore();

        mapCredentialStore.store(KEY, storedPasswordCredential, null);

        assertTrue(mapCredentialStore.exists(KEY, PasswordCredential.class));
    }

    @Test
    public void testSingleEntryStoreAndRetrieve() throws Exception {
        final MapCredentialStore mapCredentialStore = new MapCredentialStore();

        mapCredentialStore.store(KEY, storedPasswordCredential, null);

        Set<String> aliases = mapCredentialStore.getAliases();
        assertEquals("Expected alias count", 1, aliases.size());
        assertTrue("Expected alias 'key'", aliases.contains(KEY));

        final PasswordCredential retrievedPasswordCredential = mapCredentialStore.retrieve(KEY, PasswordCredential.class, null, null, null);

        assertEquals(storedPasswordCredential, retrievedPasswordCredential);
    }

    @Test
    public void testSingleEntryStoreAndRemove() throws Exception {
        final MapCredentialStore mapCredentialStore = new MapCredentialStore();

        mapCredentialStore.store(KEY, storedPasswordCredential, null);

        Set<String> aliases = mapCredentialStore.getAliases();
        assertEquals("Expected alias count", 1, aliases.size());
        assertTrue("Expected alias 'key'", aliases.contains(KEY));

        mapCredentialStore.remove(KEY, PasswordCredential.class, null, null);
        final PasswordCredential retrievedPasswordCredential = mapCredentialStore.retrieve(KEY, PasswordCredential.class, null, null, null);

        assertNull(retrievedPasswordCredential);
    }
}
