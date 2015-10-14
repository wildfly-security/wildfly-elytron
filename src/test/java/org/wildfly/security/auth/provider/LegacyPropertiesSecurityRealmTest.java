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

package org.wildfly.security.auth.provider;

import static org.wildfly.security.auth.provider.LegacyPropertiesSecurityRealm.PROPERTIES_CLEAR_CREDENTIAL_NAME;
import static org.wildfly.security.auth.provider.LegacyPropertiesSecurityRealm.PROPERTIES_DIGEST_CREDENTIAL_NAME;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.util.ByteIterator;

/**
 * A test case for the {@link LegacyPropertiesSecurityRealm}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class LegacyPropertiesSecurityRealmTest {

    private static final String ELYTRON_PASSWORD_HASH = "c588863654f886d1caae4d8af47107b7";
    private static final String ELYTRON_PASSWORD_CLEAR = "passwd12#$";

    private static final Provider provider = new WildFlyElytronProvider();

    @BeforeClass
    public static void add() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void remove() {
        Security.removeProvider(provider.getName());
    }

    /**
     * Test case to verify that the default properties file can be loaded.
     * @throws IOException
     */
    @Test
    public void testDefaultFile() throws IOException {
        SecurityRealm realm = LegacyPropertiesSecurityRealm.builder()
          .setPasswordsStream(this.getClass().getResourceAsStream("empty.properties"))
          .build();

        assertNotNull("SecurityRealm", realm);
    }

    /**
     * Test that the realm can handle the properties file where the passwords are stored in the clear.
     */
    @Test
    public void testPlainFile() throws Exception {
        SecurityRealm realm = LegacyPropertiesSecurityRealm.builder()
                .setPasswordsStream(this.getClass().getResourceAsStream("clear.properties"))
                .setPlainText(true)
                .build();

        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR);
        Password goodGuess = passwordFactory.generatePassword(new ClearPasswordSpec(ELYTRON_PASSWORD_CLEAR.toCharArray()));
        Password badGuess = passwordFactory.generatePassword(new ClearPasswordSpec("I will hack you".toCharArray()));

        assertEquals("ClearPassword", CredentialSupport.FULLY_SUPPORTED, realm.getCredentialSupport(PROPERTIES_CLEAR_CREDENTIAL_NAME));
        assertEquals("DigestPassword", CredentialSupport.OBTAINABLE_ONLY, realm.getCredentialSupport(PROPERTIES_DIGEST_CREDENTIAL_NAME));

        RealmIdentity elytronIdentity = realm.createRealmIdentity("elytron");
        assertEquals("ClearPassword", CredentialSupport.FULLY_SUPPORTED, elytronIdentity.getCredentialSupport(PROPERTIES_CLEAR_CREDENTIAL_NAME));
        assertEquals("DigestPassword", CredentialSupport.OBTAINABLE_ONLY, elytronIdentity.getCredentialSupport(PROPERTIES_DIGEST_CREDENTIAL_NAME));

        ClearPassword elytronClear = elytronIdentity.getCredential(PROPERTIES_CLEAR_CREDENTIAL_NAME, ClearPassword.class);
        assertNotNull(elytronClear);
        assertEquals(ELYTRON_PASSWORD_CLEAR, new String(elytronClear.getPassword()));

        DigestPassword elytronDigest = elytronIdentity.getCredential(PROPERTIES_DIGEST_CREDENTIAL_NAME, DigestPassword.class);
        assertNotNull(elytronDigest);
        String actualHex = ByteIterator.ofBytes(elytronDigest.getDigest()).hexEncode().drainToString();
        assertEquals(ELYTRON_PASSWORD_HASH, actualHex);

        assertTrue(elytronIdentity.verifyEvidence(PROPERTIES_CLEAR_CREDENTIAL_NAME, goodGuess));
        assertFalse(elytronIdentity.verifyEvidence(PROPERTIES_CLEAR_CREDENTIAL_NAME, badGuess));

        elytronIdentity.dispose();

        RealmIdentity badIdentity = realm.createRealmIdentity("noone");
        assertEquals("ClearPassword", CredentialSupport.UNSUPPORTED, badIdentity.getCredentialSupport(PROPERTIES_CLEAR_CREDENTIAL_NAME));
        assertEquals("DigestPassword", CredentialSupport.UNSUPPORTED, badIdentity.getCredentialSupport(PROPERTIES_DIGEST_CREDENTIAL_NAME));

        assertNull(badIdentity.getCredential(PROPERTIES_CLEAR_CREDENTIAL_NAME, Object.class));
        assertNull(badIdentity.getCredential(PROPERTIES_DIGEST_CREDENTIAL_NAME, Object.class));

        assertFalse(badIdentity.verifyEvidence(PROPERTIES_CLEAR_CREDENTIAL_NAME, goodGuess));
        assertFalse(badIdentity.verifyEvidence(PROPERTIES_CLEAR_CREDENTIAL_NAME, badGuess));

        badIdentity.dispose();
    }

    /**
     * Test that the realm can handle the properties file where the passwords are stored pre-hashed.
     */
    @Test
    public void testHashedFile() throws Exception {
        SecurityRealm realm = LegacyPropertiesSecurityRealm.builder()
                .setPasswordsStream(this.getClass().getResourceAsStream("users.properties"))
                .build();

        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR);
        Password goodGuess = passwordFactory.generatePassword(new ClearPasswordSpec(ELYTRON_PASSWORD_CLEAR.toCharArray()));
        Password badGuess = passwordFactory.generatePassword(new ClearPasswordSpec("I will hack you".toCharArray()));

        assertEquals("ClearPassword", CredentialSupport.VERIFIABLE_ONLY, realm.getCredentialSupport(PROPERTIES_CLEAR_CREDENTIAL_NAME));
        assertEquals("DigestPassword", CredentialSupport.OBTAINABLE_ONLY, realm.getCredentialSupport(PROPERTIES_DIGEST_CREDENTIAL_NAME));

        RealmIdentity elytronIdentity = realm.createRealmIdentity("elytron");
        assertEquals("ClearPassword", CredentialSupport.VERIFIABLE_ONLY, elytronIdentity.getCredentialSupport(PROPERTIES_CLEAR_CREDENTIAL_NAME));
        assertEquals("DigestPassword", CredentialSupport.OBTAINABLE_ONLY, elytronIdentity.getCredentialSupport(PROPERTIES_DIGEST_CREDENTIAL_NAME));

        assertNull(elytronIdentity.getCredential(PROPERTIES_CLEAR_CREDENTIAL_NAME, Object.class));

        DigestPassword elytronDigest = elytronIdentity.getCredential(PROPERTIES_DIGEST_CREDENTIAL_NAME, DigestPassword.class);
        assertNotNull(elytronDigest);
        String actualHex = ByteIterator.ofBytes(elytronDigest.getDigest()).hexEncode().drainToString();
        assertEquals(ELYTRON_PASSWORD_HASH, actualHex);

        assertTrue(elytronIdentity.verifyEvidence(PROPERTIES_DIGEST_CREDENTIAL_NAME, goodGuess));
        assertFalse(elytronIdentity.verifyEvidence(PROPERTIES_DIGEST_CREDENTIAL_NAME, badGuess));

        elytronIdentity.dispose();

        RealmIdentity badIdentity = realm.createRealmIdentity("noone");
        assertEquals("ClearPassword", CredentialSupport.UNSUPPORTED, badIdentity.getCredentialSupport(PROPERTIES_CLEAR_CREDENTIAL_NAME));
        assertEquals("DigestPassword", CredentialSupport.UNSUPPORTED, badIdentity.getCredentialSupport(PROPERTIES_DIGEST_CREDENTIAL_NAME));

        assertNull(badIdentity.getCredential(PROPERTIES_CLEAR_CREDENTIAL_NAME, Object.class));
        assertNull(badIdentity.getCredential(PROPERTIES_DIGEST_CREDENTIAL_NAME, Object.class));

        assertFalse(badIdentity.verifyEvidence(PROPERTIES_DIGEST_CREDENTIAL_NAME, goodGuess));
        assertFalse(badIdentity.verifyEvidence(PROPERTIES_DIGEST_CREDENTIAL_NAME, badGuess));

        badIdentity.dispose();
    }
}
