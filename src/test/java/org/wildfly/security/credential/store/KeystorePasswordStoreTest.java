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
package org.wildfly.security.credential.store;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;


/**
 * {@code KeyStoreCredentialStore} tests
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class KeystorePasswordStoreTest {

    private static final Provider provider = new WildFlyElytronProvider();

    private static Map<String, String> stores = new HashMap<>();
    private static String BASE_STORE_DIRECTORY = "target/ks-cred-stores";
    static {
        stores.put("ONE", BASE_STORE_DIRECTORY + "/keystore1.jceks");
        stores.put("TWO", BASE_STORE_DIRECTORY + "/keystore2.jceks");
        stores.put("THREE", BASE_STORE_DIRECTORY + "/keystore3.jceks");
    }

    /**
     * Clean all vaults.
     */
    public static void cleanCredentialStores() {
        File dir = new File(BASE_STORE_DIRECTORY);
        dir.mkdirs();

        for (String f: stores.values()) {
            File file = new File(f);
            file.delete();
        }
    }

    static CredentialStore newCredentialStoreInstance() throws NoSuchAlgorithmException {
        return CredentialStore.getInstance(KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE);
    }

    /**
     * Convert {@code char[]} password to {@code PasswordCredential}
     * @param password to convert
     * @return new {@code PasswordCredential}
     * @throws UnsupportedCredentialTypeException should never happen as we have only supported types and algorithms
     */
    PasswordCredential createCredentialFromPassword(char[] password) throws UnsupportedCredentialTypeException {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
            return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedCredentialTypeException(e);
        }
    }

    /**
     * Converts {@code PasswordCredential} to {@code char[]} password
     * @param passwordCredential to convert
     * @return plain text password as {@code char[]}
     */
    char[] getPasswordFromCredential(PasswordCredential passwordCredential) {
        Assert.assertNotNull("passwordCredential parameter", passwordCredential);
        return passwordCredential.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword);
    }

    /**
     * Register security provider containing {@link org.wildfly.security.credential.store.CredentialStoreSpi} implementation.
     */
    @BeforeClass
    public static void setup() throws Exception {
        Security.addProvider(provider);
        cleanCredentialStores();
        // setup vaults that need to be complete before a test starts
        CredentialStoreBuilder.get().setKeyStoreFile(stores.get("TWO"))
                .setKeyStoreType("JCEKS")
                .setKeyStorePassword("secret_store_TWO")
                .addPassword("alias1", "secret-password-1")
                .addPassword("alias2", "secret-password-2")
                .build();
        CredentialStoreBuilder.get().setKeyStoreFile(stores.get("THREE"))
                .setKeyStoreType("JCEKS")
                .setKeyStorePassword("secret_store_THREE")
                .addPassword("db-pass-1", "1-secret-info")
                .addPassword("db-pass-2", "2-secret-info")
                .addPassword("db-pass-3", "3-secret-info")
                .addPassword("db-pass-4", "4-secret-info")
                .addPassword("db-pass-5", "5-secret-info")
                .build();

    }

    /**
     * Remove security provider.
     */
    @AfterClass
    public static void remove() {
        Security.removeProvider(provider.getName());
    }

    /**
     * Basic {@code CredentialStore} test.
     * @throws Exception when problem occurs
     */
    @Test
    public void basicKeystorePasswordStoreTest() throws Exception {

        char[] password1 = "db-secret-pass1".toCharArray();
        char[] password2 = "PangmaŠišatá".toCharArray();
        char[] password3 = "Červenavý střizlíček a žľúva ďobali ve šťavnatých ocúnech".toCharArray();

        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", stores.get("ONE"));
        csAttributes.put("keyStoreType", "JCEKS");
        csAttributes.put("create", Boolean.TRUE.toString());

        String passwordAlias1 = "db1-password1";
        String passwordAlias2 = "db1-password2";
        String passwordAlias3 = "db1-password3";



        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes, new CredentialStore.CredentialSourceProtectionParameter(
            IdentityCredentials.NONE.withCredential(createCredentialFromPassword("test".toCharArray()))
        ));

        cs.store(passwordAlias1, createCredentialFromPassword(password1));
        cs.store(passwordAlias2, createCredentialFromPassword(password2));
        cs.store(passwordAlias3, createCredentialFromPassword(password3));
        cs.flush();

        Assert.assertArrayEquals(password2, getPasswordFromCredential(cs.retrieve(passwordAlias2, PasswordCredential.class)));
        Assert.assertArrayEquals(password1, getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));
        Assert.assertArrayEquals(password3, getPasswordFromCredential(cs.retrieve(passwordAlias3, PasswordCredential.class)));
    }

    /**
     * Basic {@code CredentialStore} test on already existing store.
     * @throws Exception when problem occurs
     */
    @Test
    public void basicTestOnAlreadyCreatedKeystorePasswordStore() throws Exception {
        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", stores.get("TWO"));
        csAttributes.put("keyStoreType", "JCEKS");

        // testing if KeystorePasswordStore.MODIFIABLE default value is "true", so not setting anything

        String passwordAlias1 = "alias1";
        String passwordAlias2 = "alias2";

        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes, new CredentialStore.CredentialSourceProtectionParameter(
            IdentityCredentials.NONE.withCredential(
                new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "secret_store_TWO".toCharArray()))
            )
        ));

        // expected entries there
        Assert.assertArrayEquals("secret-password-1".toCharArray(), getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));
        Assert.assertArrayEquals("secret-password-2".toCharArray(), getPasswordFromCredential(cs.retrieve(passwordAlias2, PasswordCredential.class)));

        // retrieve non-existent entry
        Assert.assertNull(cs.retrieve("wrong_alias", PasswordCredential.class));

        // store test
        cs.store("db-password", createCredentialFromPassword("supersecretdbpass".toCharArray()));

        // remove test
        cs.remove(passwordAlias2, PasswordCredential.class);

        Set<String> aliases = cs.getAliases();
        Assert.assertFalse("Alias \"" + passwordAlias2 + "\" should be removed.", aliases.contains(passwordAlias2));

        if (!cs.exists("db-password", PasswordCredential.class)) {
            Assert.fail("'db-password'" + " has to exist");
        }

        if (cs.exists(passwordAlias2, PasswordCredential.class)) {
            Assert.fail(passwordAlias2 + " has been removed from the vault, but it exists");
        }
    }
}
