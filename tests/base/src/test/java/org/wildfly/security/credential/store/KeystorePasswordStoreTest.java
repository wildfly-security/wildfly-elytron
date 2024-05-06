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
import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Supplier;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;


/**
 * {@code KeyStoreCredentialStore} tests
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>,
 *         <a href="mailto:hsvabek@redhat.com">Hynek Svabek</a>.
 */
public class KeystorePasswordStoreTest {

    private static Map<String, String> stores = new HashMap<>();
    private static String BASE_STORE_DIRECTORY = "target/ks-cred-stores";
    static {
        stores.put("ONE", BASE_STORE_DIRECTORY + "/keystore1.jceks");
        stores.put("TWO", BASE_STORE_DIRECTORY + "/keystore2.jceks");
        stores.put("THREE", BASE_STORE_DIRECTORY + "/keystore3.jceks");
        stores.put("TO_DELETE", BASE_STORE_DIRECTORY + "/keystore4.jceks");
    }

    /**
     * Clean all vaults.
     */
    private static void cleanCredentialStores() {
        File dir = new File(BASE_STORE_DIRECTORY);
        dir.mkdirs();

        for (String f: stores.values()) {
            File file = new File(f);
            file.delete();
        }
    }

    private static CredentialStore newCredentialStoreInstance() throws NoSuchAlgorithmException {
        return CredentialStore.getInstance(KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE, WildFlyElytronCredentialStoreProvider.getInstance());
    }

    /**
     * Convert {@code char[]} password to {@code PasswordCredential}
     * @param password to convert
     * @return new {@code PasswordCredential}
     * @throws UnsupportedCredentialTypeException should never happen as we have only supported types and algorithms
     */
    private PasswordCredential createCredentialFromPassword(char[] password) throws UnsupportedCredentialTypeException {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, WildFlyElytronPasswordProvider.getInstance());
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
    private char[] getPasswordFromCredential(PasswordCredential passwordCredential) {
        Assert.assertNotNull("passwordCredential parameter", passwordCredential);
        return passwordCredential.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword);
    }

    /**
     * Register security provider containing {@link org.wildfly.security.credential.store.CredentialStoreSpi} implementation.
     */
    @BeforeClass
    public static void setup() throws Exception {
        cleanCredentialStores();
        // setup vaults that need to be complete before a test starts
        CredentialStoreBuilder.get().setKeyStoreFile(stores.get("TWO"))
                .setProviders(WildFlyElytronCredentialStoreProvider.getInstance())
                .setKeyStoreType("JCEKS")
                .setKeyStorePassword("secret_store_TWO")
                .addPassword("alias1", "secret-password-1")
                .addPassword("alias2", "secret-password-2")
                .build();
        CredentialStoreBuilder.get().setKeyStoreFile(stores.get("THREE"))
                .setProviders(WildFlyElytronCredentialStoreProvider.getInstance())
                .setKeyStoreType("JCEKS")
                .setKeyStorePassword("secret_store_THREE")
                .addPassword("db-pass-1", "1-secret-info")
                .addPassword("db-pass-2", "2-secret-info")
                .addPassword("db-pass-3", "3-secret-info")
                .addPassword("db-pass-4", "4-secret-info")
                .addPassword("db-pass-5", "5-secret-info")
                .build();
        CredentialStoreBuilder.get().setKeyStoreFile(stores.get("TO_DELETE"))
                .setProviders(WildFlyElytronCredentialStoreProvider.getInstance())
                .setKeyStorePassword("secret_store_DELETE")
                .addPassword("alias1", "secret-password-1")
                .addPassword("alias2", "secret-password-2")
                .build();

    }

    /**
     * After initialize Credential Store is removed backend CS file. This file must be created again when there is added new
     * entry to store.
     *
     * @throws NoSuchAlgorithmException
     * @throws CredentialStoreException
     * @throws UnsupportedCredentialTypeException
     */
    @Test
    public void testRecreatingKSTest()
        throws NoSuchAlgorithmException, CredentialStoreException, UnsupportedCredentialTypeException {

        File ks = new File(stores.get("TO_DELETE"));
        if (!ks.exists()) {
            Assert.fail("KeyStore must exists!");
        }

        char[] password1 = "secret-password1".toCharArray();
        char[] password2 = "secret-password2".toCharArray();

        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", stores.get("TO_DELETE"));
        csAttributes.put("keyStoreType", "JCEKS");

        String passwordAlias1 = "passAlias1";
        String passwordAlias2 = "passAlias2";

        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes,
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(
                    ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "secret_store_DELETE".toCharArray())))),
                new Provider[]{WildFlyElytronPasswordProvider.getInstance()}
        );

        cs.store(passwordAlias1, createCredentialFromPassword(password1));
        cs.store(passwordAlias2, createCredentialFromPassword(password2));

        Assert.assertArrayEquals(password1, getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));

        if (!ks.delete()) {
            Assert.fail("KeyStore [" + ks.getAbsolutePath() + "] delete fail");
        }

        Assert.assertArrayEquals(password1, getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));
        // load new entry (in memory)
        Assert.assertArrayEquals(password2, getPasswordFromCredential(cs.retrieve(passwordAlias2, PasswordCredential.class)));

        cs.store("abc", createCredentialFromPassword(password1));
        cs.flush();
        if (!ks.exists()) {
            Assert.fail("KeyStore [" + ks.getAbsolutePath() + "] must exist yet.");
        }
    }

    /**
     * Credential Store is set to read-only.
     *
     * @throws NoSuchAlgorithmException
     * @throws CredentialStoreException
     * @throws UnsupportedCredentialTypeException
     */
    @Test
    public void testReadOnly() throws NoSuchAlgorithmException, CredentialStoreException, UnsupportedCredentialTypeException {

        char[] password1 = "secret-password1".toCharArray();

        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", stores.get("TWO"));
        csAttributes.put("keyStoreType", "JCEKS");
        csAttributes.put("modifiable", "false");

        String passwordAlias1 = "passAlias_readonly";

        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes,
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(
                    ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "secret_store_TWO".toCharArray())))));

        try {
            cs.store(passwordAlias1, createCredentialFromPassword(password1));
            Assert.fail("This Credential Store should be read-only.");
        } catch (CredentialStoreException e) {
            // expected
        }

        Assert.assertNull("'" + passwordAlias1 + "' must not be in this Credential Store because is read-only.",
            cs.retrieve(passwordAlias1, PasswordCredential.class));
    }

    /**
     * Credential Store entries must be case insensitive.
     *
     * @throws NoSuchAlgorithmException
     * @throws CredentialStoreException
     * @throws UnsupportedCredentialTypeException
     */
    @Test
    public void testCaseInsensitiveAlias()
        throws NoSuchAlgorithmException, CredentialStoreException, UnsupportedCredentialTypeException {
        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", stores.get("TWO"));
        csAttributes.put("keyStoreType", "JCEKS");

        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes,
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(
                    ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "secret_store_TWO".toCharArray())))),
                new Provider[]{WildFlyElytronPasswordProvider.getInstance()});

        // store test
        String caseSensitive1 = "caseSensitiveName";
        String caseSensitive2 = caseSensitive1.toUpperCase();
        char[] newPassword1 = "new-secret-passONE".toCharArray();
        char[] newPassword2 = "new-secret-passTWO".toCharArray();
        cs.store(caseSensitive1, createCredentialFromPassword(newPassword1));

        if (!cs.exists(caseSensitive1, PasswordCredential.class)) {
            Assert.fail("'" + caseSensitive1 + "'" + " must exist");
        }
        if (!cs.exists(caseSensitive1.toLowerCase(), PasswordCredential.class)) {
            Assert.fail("'" + caseSensitive1.toLowerCase() + "'" + " in lowercase must exist");
        }
        cs.remove(caseSensitive1, PasswordCredential.class);
        if (cs.exists(caseSensitive1, PasswordCredential.class)) {
            Assert.fail(caseSensitive1 + " has been removed from the vault, but it exists");
        }

        // this is actually alias update
        cs.store(caseSensitive2, createCredentialFromPassword(newPassword2));

        Assert.assertArrayEquals(newPassword2,
            getPasswordFromCredential(cs.retrieve(caseSensitive1, PasswordCredential.class)));
        Assert.assertArrayEquals(newPassword2,
            getPasswordFromCredential(cs.retrieve(caseSensitive2, PasswordCredential.class)));
        Assert.assertArrayEquals(newPassword2,
            getPasswordFromCredential(cs.retrieve(caseSensitive1.toLowerCase(), PasswordCredential.class)));

        // Reaload CS keystore from filesystem
        csAttributes.put("location", stores.get("TWO"));
        csAttributes.put("keyStoreType", "JCEKS");
        csAttributes.put("modifiable", "false");

        CredentialStore csReloaded = newCredentialStoreInstance();
        csReloaded.initialize(csAttributes,
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(
                    ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "secret_store_TWO".toCharArray())))));

        Assert.assertArrayEquals(newPassword2,
            getPasswordFromCredential(cs.retrieve(caseSensitive1, PasswordCredential.class)));
        Assert.assertArrayEquals(newPassword2,
            getPasswordFromCredential(cs.retrieve(caseSensitive2, PasswordCredential.class)));
        Assert.assertArrayEquals(newPassword2,
            getPasswordFromCredential(cs.retrieve(caseSensitive1.toLowerCase(), PasswordCredential.class)));
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
        ), new Provider[] {WildFlyElytronPasswordProvider.getInstance()});

        cs.store(passwordAlias1, createCredentialFromPassword(password1));
        cs.store(passwordAlias2, createCredentialFromPassword(password2));
        cs.store(passwordAlias3, createCredentialFromPassword(password3));
        cs.flush();

        Assert.assertArrayEquals(password2, getPasswordFromCredential(cs.retrieve(passwordAlias2, PasswordCredential.class)));
        Assert.assertArrayEquals(password1, getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));
        Assert.assertArrayEquals(password3, getPasswordFromCredential(cs.retrieve(passwordAlias3, PasswordCredential.class)));

        char[] newPassword1 = "new-secret-pass1".toCharArray();

        // update test
        cs.store(passwordAlias1, createCredentialFromPassword(newPassword1));
        Assert.assertArrayEquals(newPassword1,
            getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));

        // remove test
        cs.remove(passwordAlias2, PasswordCredential.class);

        if (cs.exists(passwordAlias2, PasswordCredential.class)) {
            Assert.fail(passwordAlias2 + " has been removed from the vault, but it exists");
        }
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
        ), new Provider[]{WildFlyElytronPasswordProvider.getInstance()});

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

        char[] newPassword1 = "new-secret-pass1".toCharArray();

        // update test
        cs.store(passwordAlias1, createCredentialFromPassword(newPassword1));
        Assert.assertArrayEquals(newPassword1,
            getPasswordFromCredential(cs.retrieve(passwordAlias1, PasswordCredential.class)));
    }

    @Test
    public void testParallelAccessToCS()
        throws UnsupportedCredentialTypeException, CredentialStoreException, NoSuchAlgorithmException {
        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", stores.get("ONE"));
        csAttributes.put("keyStoreType", "JCEKS");
        csAttributes.put("create", Boolean.TRUE.toString());


        CredentialStore cs = newCredentialStoreInstance();
        cs.initialize(csAttributes, new CredentialStore.CredentialSourceProtectionParameter(
            IdentityCredentials.NONE.withCredential(createCredentialFromPassword("test".toCharArray()))),
                new Provider[]{WildFlyElytronPasswordProvider.getInstance()}
        );

        cs.flush();

        final ExecutorService executor = Executors.newFixedThreadPool(4);
        ReadWriteLock readWriteLock = getCsLock(cs);
        try {
            // store
            Supplier<Callable<Object>> storeTask = () -> prepareParallelCsStoreTask(cs, executor, readWriteLock);
            testAccessFromMultipleCredentialStores(executor, storeTask);
            // remove
            Supplier<Callable<Object>> removeTask = () -> prepareParallelCsRemoveTask(cs, executor, readWriteLock);
            testAccessFromMultipleCredentialStores(executor, removeTask);
        } finally {
            executor.shutdown();
            if (readWriteLock.readLock().tryLock()) {
                readWriteLock.readLock().unlock();
            }
        }
    }

    private void testAccessFromMultipleCredentialStores(final ExecutorService executor, Supplier<Callable<Object>> csTask) {
        try {
            Callable<Object> task = csTask.get();

            Future<Object> task1Future = executor.submit(task);
            task1Future.get(15, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Callable<Object> prepareParallelCsStoreTask(CredentialStore cs, final ExecutorService executor, ReadWriteLock readWriteLock) {
        Callable<Object> task1 = new Callable<Object>() {
            @Override
            public Object call() throws Exception {
                String aliasName = addRandomSuffix("alias");

                readWriteLock.readLock().lock();

                Callable<Object> task2 = new Callable<Object>() {
                    @Override
                    public Object call() throws Exception {
                        cs.store(aliasName, createCredentialFromPassword("secret".toCharArray()));
                        return null;
                    }
                };

                Future<Object> task2Future = executor.submit(task2);
                try{
                    task2Future.get(1, TimeUnit.SECONDS);
                    Assert.fail("We expect timeout.");
                } catch (TimeoutException e) {
                    // expected
                }

                if (cs.exists(aliasName, PasswordCredential.class)) {
                    throw new IllegalStateException(String.format("Alias '%s' doesn't must exist yet!", aliasName));
                }

                readWriteLock.readLock().unlock();
                task2Future.get(10, TimeUnit.SECONDS);

                if (!cs.exists(aliasName, PasswordCredential.class)) {
                    throw new IllegalStateException(String.format("Alias '%s' have to exist!", aliasName));
                }
                return null;
            }
        };
        return task1;
    }

    private Callable<Object> prepareParallelCsRemoveTask(CredentialStore cs, final ExecutorService executor,
        ReadWriteLock readWriteLock) {
        Callable<Object> task1 = new Callable<Object>() {
            @Override
            public Object call() throws Exception {
                String aliasName = addRandomSuffix("alias");
                cs.store(aliasName, createCredentialFromPassword("secret".toCharArray()));

                readWriteLock.readLock().lock();

                Callable<Object> task2 = new Callable<Object>() {
                    @Override
                    public Object call() throws Exception {
                        cs.remove(aliasName, PasswordCredential.class);
                        return null;
                    }
                };

                Future<Object> task2Future = executor.submit(task2);
                try {
                    task2Future.get(1, TimeUnit.SECONDS);
                    Assert.fail("We expect timeout.");
                } catch (TimeoutException e) {
                    // expected
                }

                if (!cs.exists(aliasName, PasswordCredential.class)) {
                    throw new IllegalStateException(String.format("Alias '%s' must exist!", aliasName));
                }

                readWriteLock.readLock().unlock();
                task2Future.get(10, TimeUnit.SECONDS);

                if (cs.exists(aliasName, PasswordCredential.class)) {
                    throw new IllegalStateException(String.format("Alias '%s' should be deleted!", aliasName));
                }
                return null;
            }
        };
        return task1;
    }

    private ReadWriteLock getCsLock(CredentialStore cs) {
        ReadWriteLock readWriteLock;
        try{
            Field f = CredentialStore.class.getDeclaredField("spi");
            f.setAccessible(true);
            KeyStoreCredentialStore csSpi = (KeyStoreCredentialStore) f.get(cs);
            f.setAccessible(false);

            f = KeyStoreCredentialStore.class.getDeclaredField("readWriteLock");
            f.setAccessible(true);
            readWriteLock = (ReadWriteLock) f.get(csSpi);
            f.setAccessible(false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return readWriteLock;
    }

    private static String addRandomSuffix(String str) {
        return str + "_" + getRandomString();
    }

    private static String getRandomString() {
        return RandomStringUtils.randomAlphanumeric(10);
    }
}
