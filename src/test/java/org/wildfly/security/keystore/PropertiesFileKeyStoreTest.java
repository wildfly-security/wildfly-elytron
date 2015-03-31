/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.keystore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.interfaces.UnixMD5CryptPassword;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;

/**
 * Testsuite for the {@link PropertiesKeyStoreSpi}.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class PropertiesFileKeyStoreTest {

    private static final Provider provider = new WildFlyElytronProvider();

    @BeforeClass
    public static void register() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void remove() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testGetSetDelete() throws Exception {

        PasswordFactory passwordFactory = PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_MD5);
        final Password dukePassword = passwordFactory.generatePassword
                (new EncryptablePasswordSpec("testpassword".toCharArray(),
                        new DigestPasswordAlgorithmSpec(DigestPassword.ALGORITHM_DIGEST_MD5, "testuser", "testrealm")));

        // instantiate and initialize an empty properties-based keystore.
        final KeyStore keyStore = KeyStore.getInstance("PropertiesFile");
        keyStore.load(new InputStream() {
            public int read() throws IOException {
                return -1;
            }
        }, null);

        // add an entry to the new keystore and check if the entry was correctly added.
        keyStore.setEntry("testuser", new EnablingPasswordEntry(dukePassword), null);
        final KeyStore.Entry entry = keyStore.getEntry("testuser", null);
        assertNotNull("Missing entry", entry);
        assertTrue("Wrong entry type", entry instanceof EnablingPasswordEntry);
        final Password storedPassword = ((EnablingPasswordEntry) entry).getPassword();
        assertNotNull(storedPassword);
        assertTrue("Wrong password type", storedPassword instanceof DigestPassword);
        assertSame(dukePassword, storedPassword);
        final DigestPassword digestPassword = (DigestPassword) storedPassword;
        assertEquals("Invalid username in password", "testuser", digestPassword.getUsername());
        assertEquals("Invalid realm in password", "testrealm", digestPassword.getRealm());
        assertTrue(PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_MD5).verify(dukePassword, "testpassword".toCharArray()));

        // try adding an entry with an invalid password type.
        passwordFactory = PasswordFactory.getInstance(UnixMD5CryptPassword.ALGORITHM_CRYPT_MD5);
        final byte[] b = new byte[16];
        ThreadLocalRandom.current().nextBytes(b);
        Password wrongPassword = passwordFactory.generatePassword(new EncryptablePasswordSpec("swordfish".toCharArray(), new HashedPasswordAlgorithmSpec(16, b)));
        try {
            keyStore.setEntry("anotheruser", new EnablingPasswordEntry(wrongPassword), null);
            fail("Wrong password type should have been rejected");
        } catch (KeyStoreException e) {
            assertTrue(e.getMessage().startsWith("ELY00045"));
        }

        // now try adding an entry with the right type but wrong algorithm.
        passwordFactory = PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_SHA_256);
        wrongPassword = passwordFactory.generatePassword(new EncryptablePasswordSpec("anotherpasswd".toCharArray(),
                new DigestPasswordAlgorithmSpec(DigestPassword.ALGORITHM_DIGEST_SHA_256, "anotheruser", "testrealm")));
        try {
            keyStore.setEntry("anotheruser", new EnablingPasswordEntry(wrongPassword), null);
            fail("Wrong password algorithm should have been rejected");
        } catch (KeyStoreException e) {
            assertTrue(e.getMessage().startsWith("ELY00048"));
        }

        // finally try adding an entry with the right type but the wrong realm.
        passwordFactory = PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_MD5);
        wrongPassword = passwordFactory.generatePassword(new EncryptablePasswordSpec("anotherpasswd".toCharArray(),
                new DigestPasswordAlgorithmSpec(DigestPassword.ALGORITHM_DIGEST_MD5, "anotheruser", "anotherrealm")));
        try {
            keyStore.setEntry("anotheruser", new EnablingPasswordEntry(wrongPassword), null);
            fail("Wrong password realm should have been rejected");
        } catch (KeyStoreException e) {
            assertTrue(e.getMessage().startsWith("ELY00047"));
        }

        // delete the entry that was originally added - the keystore should now be empty.
        keyStore.deleteEntry("testuser");
        Enumeration aliases = keyStore.aliases();
        assertFalse(aliases.hasMoreElements());

        // when deleting the last entry, the realm should have been reset - we must be able now to set an entry with a different realm.
        keyStore.setEntry("anotheruser", new EnablingPasswordEntry(wrongPassword), null);
        assertNotNull("Missing entry", keyStore.getEntry("anotheruser", null));
    }

    @Test
    public void testLoadAndStore() throws Exception {

        final String realmName = "ManagementRealm";
        final String[] testUsers = new String[] {"elytron", "javajoe", "javaduke"};
        final String[] testPasswords = new String[] {"passwd12#$", "$#21pass", "dukepass!@34"};

        // initialize the keystore, this time loading the users from a test properties file.
        final InputStream stream = this.getClass().getResourceAsStream("users.properties");
        final KeyStore keyStore = KeyStore.getInstance("PropertiesFile");
        keyStore.load(stream, null);

        // verify the keystore has the right number of entries and contains all expected aliases.
        Enumeration<String> ksAliases = keyStore.aliases();
        List<String> aliases = new ArrayList<>();
        while (ksAliases.hasMoreElements()) {
            aliases.add(ksAliases.nextElement());
        }
        assertEquals("Unexpected number of entries", 2, aliases.size());
        assertTrue("Expected alias not found", keyStore.containsAlias(testUsers[0]));
        assertTrue("Expected alias not found", keyStore.containsAlias(testUsers[1]));

        // check the contents of each entry.
        EnablingPasswordEntry passwordEntry = (EnablingPasswordEntry) keyStore.getEntry(testUsers[0], null);
        assertNotNull("Missing entry", passwordEntry);
        assertTrue(passwordEntry.isEnabled());
        DigestPassword digestPassword = (DigestPassword) passwordEntry.getPassword();
        assertEquals("Invalid username in password", testUsers[0], digestPassword.getUsername());
        assertEquals("Invalid realm in password", realmName, digestPassword.getRealm());
        assertTrue(PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_MD5).verify(digestPassword, testPasswords[0].toCharArray()));

        passwordEntry = (EnablingPasswordEntry) keyStore.getEntry(testUsers[1], null);
        assertNotNull("Missing entry", passwordEntry);
        assertFalse(passwordEntry.isEnabled());
        digestPassword = (DigestPassword) passwordEntry.getPassword();
        assertEquals("Invalid username in password", testUsers[1], digestPassword.getUsername());
        assertEquals("Invalid realm in password", realmName, digestPassword.getRealm());
        assertTrue(PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_MD5).verify(digestPassword, testPasswords[1].toCharArray()));

        // re-enable javajoe.
        passwordEntry.enable();

        // add a new disabled entry to the keystore and then write it back to a file.
        final PasswordFactory passwordFactory = PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_MD5);
        final Password dukePassword = passwordFactory.generatePassword
                (new EncryptablePasswordSpec(testPasswords[2].toCharArray(),
                        new DigestPasswordAlgorithmSpec(DigestPassword.ALGORITHM_DIGEST_MD5, testUsers[2], realmName)));
        keyStore.setEntry(testUsers[2], new EnablingPasswordEntry(dukePassword, false), null);

        final File file = new File(System.getProperty("java.io.tmpdir") + "/changed.properties");
        try {
            keyStore.store(new FileOutputStream(file), null);

            // reload the kesytore from the new file and verify it contains all expected entries.
            keyStore.load(new FileInputStream(file), null);
            ksAliases = keyStore.aliases();
            aliases = new ArrayList<>();
            while (ksAliases.hasMoreElements()) {
                aliases.add(ksAliases.nextElement());
            }
            assertEquals("Unexpected number of entries", 3, aliases.size());
            for (String username : testUsers) {
                assertTrue("Expected alias not found", aliases.contains(username));
            }

            passwordEntry = (EnablingPasswordEntry) keyStore.getEntry(testUsers[0], null);
            assertNotNull("Missing entry", passwordEntry);
            assertTrue(passwordEntry.isEnabled());
            digestPassword = (DigestPassword) passwordEntry.getPassword();
            assertEquals("Invalid username in password", testUsers[0], digestPassword.getUsername());
            assertEquals("Invalid realm in password", realmName, digestPassword.getRealm());
            assertTrue(PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_MD5).verify(digestPassword, testPasswords[0].toCharArray()));

            passwordEntry = (EnablingPasswordEntry) keyStore.getEntry(testUsers[1], null);
            assertNotNull("Missing entry", passwordEntry);
            assertTrue(passwordEntry.isEnabled());
            digestPassword = (DigestPassword) passwordEntry.getPassword();
            assertEquals("Invalid username in password", testUsers[1], digestPassword.getUsername());
            assertEquals("Invalid realm in password", realmName, digestPassword.getRealm());
            assertTrue(PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_MD5).verify(digestPassword, testPasswords[1].toCharArray()));

            passwordEntry = (EnablingPasswordEntry) keyStore.getEntry(testUsers[2], null);
            assertNotNull("Missing entry", passwordEntry);
            assertFalse(passwordEntry.isEnabled());
            digestPassword = (DigestPassword) passwordEntry.getPassword();
            assertEquals("Invalid username in password", testUsers[2], digestPassword.getUsername());
            assertEquals("Invalid realm in password", realmName, digestPassword.getRealm());
            assertTrue(PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_MD5).verify(digestPassword, testPasswords[2].toCharArray()));
        } finally {
            file.delete();
        }
    }

    /**
     * Test case to verify that the default (empty apart from comments) properties file can be loaded.
     */
    @Test
    public void testDefaultProperties() throws Exception {
        try (InputStream stream = this.getClass().getResourceAsStream("empty.properties")) {
            final KeyStore keyStore = KeyStore.getInstance("PropertiesFile");
            keyStore.load(stream, null);
        }
    }

}
