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
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.impl.KeystorePasswordStore;
import org.wildfly.security.credential.store.impl.MaskedPasswordStore;
import org.wildfly.security.password.Password;
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
        stores.put("THREE", BASE_STORE_DIRECTORY + "/keystore-3.jceks");
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
        return CredentialStore.getInstance(KeystorePasswordStore.KEY_STORE_PASSWORD_STORE);
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
        Password p = passwordCredential.getPassword();
        return ((ClearPassword)p).getPassword();
    }

    /**
     * Setup all credential stores needed by tests.
     * @throws IOException when problem occurs
     * @throws GeneralSecurityException when problem occurs
     */
    @BeforeClass
    public static void setupCredentialStores() throws Exception {
        cleanCredentialStores();
        // setup vaults that need to be complete before a test starts
        KeystorePasswordStoreBuilder.get().setKeyStoreFile(stores.get("TWO"))
                .setKeyStorePassword("secret_store_TWO", "secret_key_TWO")
                .addSecret("alias1", "secret-password-1")
                .addSecret("alias2", "secret-password-2")
                .build();
        KeystorePasswordStoreBuilder.get().setKeyStoreFile(stores.get("THREE"))
                .setKeyStorePassword("secret_store_THREE", "secret_key_THREE")
                .addSecret("db-pass-1", "1-secret-info")
                .addSecret("db-pass-2", "2-secret-info")
                .addSecret("db-pass-3", "3-secret-info")
                .addSecret("db-pass-4", "4-secret-info")
                .addSecret("db-pass-5", "5-secret-info")
                .build();

    }

    /**
     * Register security provider containing {@link org.wildfly.security.credential.store.CredentialStoreSpi} implementation.
     */
    @BeforeClass
    public static void register() {
        Security.addProvider(provider);
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

        csAttributes.put(KeystorePasswordStore.NAME, "myvault");
        csAttributes.put(KeystorePasswordStore.STORE_FILE, stores.get("ONE"));
        csAttributes.put(KeystorePasswordStore.CREATE_STORAGE, "true");
        csAttributes.put(KeystorePasswordStore.STORE_PASSWORD, "st_secret");
        csAttributes.put(KeystorePasswordStore.KEY_PASSWORD, "key_secret");

        String passwordAlias1 = "db1-password1";
        String passwordAlias2 = "db1-password2";
        String passwordAlias3 = "db1-password3";



        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes);

        cs.store(passwordAlias1, createCredentialFromPassword(password1));
        cs.store(passwordAlias2, createCredentialFromPassword(password2));
        cs.store(passwordAlias3, createCredentialFromPassword(password3));

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

        csAttributes.put(KeystorePasswordStore.NAME, "vault-two");
        csAttributes.put(KeystorePasswordStore.STORE_FILE, stores.get("TWO"));
        csAttributes.put(KeystorePasswordStore.STORE_PASSWORD, "secret_store_TWO");
        csAttributes.put(KeystorePasswordStore.KEY_PASSWORD, "secret_key_TWO");

        String passwordAlias1 = "alias1";
        String passwordAlias2 = "alias2";

        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes);

        // expected entries there
        Assert.assertArrayEquals("secret-password-1".toCharArray(), getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));
        Assert.assertArrayEquals("secret-password-2".toCharArray(), getPasswordFromCredential(cs.retrieve(passwordAlias2, PasswordCredential.class)));

        // retrieve non-existent entry
        try {
            cs.retrieve("wrong_alias", PasswordCredential.class);
            Assert.fail("this part of code cannot be reached, retrieve() should throw CredentialStoreException");
        } catch (CredentialStoreException e) {
            // do nothing all is OK
        } catch (Throwable e) {
            Assert.fail("wrong exception thrown (" + e.getMessage() + ")");
        }

        // store test
        cs.store("db-password", createCredentialFromPassword("supersecretdbpass".toCharArray()));

        // remove test
        cs.remove(passwordAlias2, PasswordCredential.class);

        if (!cs.exists("db-password", PasswordCredential.class)) {
            Assert.fail("'db-password'" + " has to exist");
        }

        if (cs.exists(passwordAlias2, PasswordCredential.class)) {
            Assert.fail(passwordAlias2 + " has been removed from the vault, but it exists");
        }
    }

    /**
     * Test checking {EXT} external master credential method.
     * @throws Exception when problem occurs
     */
    @Test
    public void testExternalPasswordTypeEXT() throws Exception {
        String masterCommand = buildExternalCommand("{EXT}", " ", "secret_store_THREE");
        String keyCommand = buildExternalCommand("{EXT}", " ", "secret_key_THREE");
        externalCredentialTestSequence(masterCommand, keyCommand, null);
    }

    /**
     * Test checking {EXT} external master credential method.
     * @throws Exception when problem occurs
     */
    @Test
    public void testExternalPasswordTypeCMD() throws Exception {
        String masterCommand = buildExternalCommand("{CMD}", ",", "secret_store_THREE");
        String keyCommand = buildExternalCommand("{CMD}", ",", "secret_key_THREE");
        externalCredentialTestSequence(masterCommand, keyCommand, null);
    }

    /**
     * Test sequence should not add or modify credential store as it will be used multiple times and
     * don't want to initialize it each time.
     * We are testing ability to open the credential store and read an entry.
     * @param masterCredentialCommand command to get master credential
     * @param keyCredentialCommand command to get key credential
     * @throws Exception
     */
    private void externalCredentialTestSequence(final String masterCredentialCommand, final String keyCredentialCommand, final Map<String, String> additionalAttributes) throws Exception {
        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put(KeystorePasswordStore.NAME, "vault-external");
        csAttributes.put(KeystorePasswordStore.STORE_FILE, stores.get("THREE"));
        csAttributes.put(KeystorePasswordStore.STORE_PASSWORD, masterCredentialCommand);
        csAttributes.put(KeystorePasswordStore.KEY_PASSWORD, keyCredentialCommand);

        if (additionalAttributes != null) {
            csAttributes.putAll(additionalAttributes);
        }

        String passwordAlias1 = "db-pass-1";
        String passwordAlias2 = "db-pass-2";

        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes);

        // expected entries there
        Assert.assertArrayEquals("1-secret-info".toCharArray(), getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));
        Assert.assertArrayEquals("2-secret-info".toCharArray(), getPasswordFromCredential(cs.retrieve(passwordAlias2, PasswordCredential.class)));

        // retrieve non-existent entry
        try {
            cs.retrieve("wrong_alias", PasswordCredential.class);
            Assert.fail("this part of code cannot be reached, retrieve() should throw CredentialStoreException");
        } catch (CredentialStoreException e) {
            // do nothing all is OK
        } catch (Throwable e) {
            Assert.fail("wrong exception thrown (" + e.getMessage() + ")");
        }

    }

    @Test
    public void testExternalPasswordTypeMasked() throws Exception {
        Map<String, String> attributes = new HashMap<>();
        attributes.put(KeystorePasswordStore.STORE_PASSWORD + "." + MaskedPasswordStore.ITERATION_COUNT, "23");
        attributes.put(KeystorePasswordStore.STORE_PASSWORD + "." + MaskedPasswordStore.SALT, "HJU90jqw");
        attributes.put(KeystorePasswordStore.KEY_PASSWORD + "." + MaskedPasswordStore.ITERATION_COUNT, "15");
        attributes.put(KeystorePasswordStore.KEY_PASSWORD + "." + MaskedPasswordStore.SALT, "12HJ0987");

        String masterCommand = "MASK-vXSK9HZ0XD8w3VPFfUY5T3xz0/./3r/3";
        String keyCommand = "MASK-BJ4IgwNW2a5V2Yuqa1dcUVE3CDtiEuai";
        externalCredentialTestSequence(masterCommand, keyCommand, attributes);
    }


    private static String buildExternalCommand(final String extOption, final String delimiter, final String argument) {
        // First check for java.exe or java as the binary
        File java = new File(System.getProperty("java.home"), "/bin/java");
        File javaExe = new File(System.getProperty("java.home"), "/bin/java.exe");
        String jre;
        if (java.exists())
            jre = java.getAbsolutePath();
        else
            jre = javaExe.getAbsolutePath();
        // Build the command to run this jre
        String cmd = jre + delimiter + "-cp" + delimiter + System.getProperty("java.class.path") + delimiter
                + CredentialCommand.class.getName() + ( argument != null ? delimiter + argument : "");
        return extOption + cmd;
    }

}
