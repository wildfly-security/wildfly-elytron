/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.vault;

import static org.junit.Assert.*;
import org.junit.Test;

import java.net.URISyntaxException;

/**
 * Set of tests for {@code VaultURIParser}.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class VaultURIParserTest {

    @Test
    public void testCorrectFullURI() {

        vaultURITestHelper("vault://myvault/vault_keystore.jceks?VAULT_PASSWORD='secret2';SALT='20'#db-password",
                "vault", "myvault", "vault_keystore.jceks", "db-password",
                "VAULT_PASSWORD", "secret2",
                "SALT", "20"
        );

        vaultURITestHelper("vault://myvault/vault_keystore.jceks?VAULT_PASSWORD='secret2';SALT='20'#db-password",
                "vault", "myvault", "vault_keystore.jceks", "db-password",
                "VAULT_PASSWORD", "secret2",
                "SALT", "20"
        );

        vaultURITestHelper("vault://myvault/file://keystore.jceks?VAULT_PASSWORD='secret2';SALT='20';key=value#db-password",
                "vault", "myvault", "file://keystore.jceks", "db-password",
                "VAULT_PASSWORD", "secret2",
                "SALT", "20",
                "key", "value"
        );

        vaultURITestHelper("vault://myvault?VAULT_PASSWORD='secret2';SALT='20';key=value#db-password",
                "vault", "myvault", null, "db-password",
                "VAULT_PASSWORD", "secret2",
                "SALT", "20",
                "key", "value"
        );

        vaultURITestHelper("vault://myvault?VAULT_PASSWORD='YW55IGNhcm5hbCBwbGVhcw==';TEST=ct6e479;key=value#db-password",
                "vault", "myvault", null, "db-password",
                "VAULT_PASSWORD", "YW55IGNhcm5hbCBwbGVhcw==",
                "TEST", "ct6e479",
                "key", "value",
                "non-existent", null
        );

        vaultURITestHelper("vault://myvault#db-password",
                "vault", "myvault", null, "db-password"
        );

        vaultURITestHelper("vault://myvault",
                "vault", "myvault", null, null
        );

        vaultURITestHelper("vault://myvault/file:///root#db-password",
                "vault", "myvault", "file:///root", "db-password"
        );
    }

    void vaultURITestHelper(String uri, String scheme, String name, String storageFile, String attribute, String... parameter) {
        VaultURIParser parser = null;
        try {
            parser = new VaultURIParser(uri);
        } catch (URISyntaxException e) {
            fail("Parser should not fail on this one " + VaultURIParser.safeVaultURI(uri) + e);
        }

        assertEquals(scheme, parser.getScheme());
        assertEquals(name, parser.getName());
        assertEquals(storageFile, parser.getStorageFile());
        assertEquals(attribute, parser.getAttribute());

        for(int i = 0; i < parameter.length / 2; i++) {
            String paramName = parameter[2 * i];
            String paramValue = parameter[2 * i + 1];
            assertEquals(paramValue, parser.getParameter(paramName));
        }

    }

    @Test(expected = URISyntaxException.class)
    public void testMalformedGeneralURI() throws Exception {
        new VaultURIParser("vault://myvault/vault_keystore.jceks?VAULT_PASSWORD='secret2';SALT='20'#db-password#another-attribute"); // two fragments
    }

    @Test(expected = URISyntaxException.class)
    public void testMalforormedVaultURI_0() throws Exception {
        new VaultURIParser("");
    }

    @Test
    public void testNameVaultReference() throws Exception {
        new VaultURIParser("//myvault");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMalforormedVaultURI_2() throws Exception {
        new VaultURIParser("vault://myvault#");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMalforormedVaultURI_3() throws Exception {
        new VaultURIParser("vault://myvault/test.jks?");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMalforormedVaultURI_4() throws Exception {
        new VaultURIParser("vault://myvault/?key1=val1;key2='val2'#");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMalforormedVaultURI_5() throws Exception {
        new VaultURIParser("vault1://myvault/file.jceks?key1=val1;key2='val2'#attrib");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMalforormedVaultURI_6() throws Exception {
        new VaultURIParser("vault://myvault/file.jceks?key1=val1;key2='val2'e#attrib");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMalforormedVaultURI_7() throws Exception {
        new VaultURIParser("vault://myvault/file.jceks?key1=val1;key2=b'val2'#attrib");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMalforormedVaultURI_8() throws Exception {
        new VaultURIParser("vault://myvault?key1=val1';key2=val2#attrib");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMalforormedVaultURI_9() throws Exception {
        new VaultURIParser("vault://myvault/file://keystore?key1=val1;key2=val2'#attrib");
    }

}
