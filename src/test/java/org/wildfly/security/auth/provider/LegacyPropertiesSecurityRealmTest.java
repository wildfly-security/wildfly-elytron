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
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.util.ByteIterator;

/**
 * A test case for the {@link LegacyPropertiesSecurityRealm}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class LegacyPropertiesSecurityRealmTest {

    private static final String PROPERTIES_CLEAR_CREDENTIAL_NAME = "the-clear-one-it-is";
    private static final String PROPERTIES_DIGEST_CREDENTIAL_NAME = "the-digested-one-it-is";
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

        PasswordGuessEvidence goodGuess = new PasswordGuessEvidence(ELYTRON_PASSWORD_CLEAR.toCharArray());
        PasswordGuessEvidence badGuess = new PasswordGuessEvidence("I will hack you".toCharArray());

        assertEquals("ClearPassword", SupportLevel.SUPPORTED, realm.getCredentialAcquireSupport(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR));
        assertEquals("DigestPassword", SupportLevel.SUPPORTED, realm.getCredentialAcquireSupport(PasswordCredential.class, DigestPassword.ALGORITHM_DIGEST_MD5));
        assertEquals("Verify", SupportLevel.SUPPORTED, realm.getEvidenceVerifySupport(PasswordGuessEvidence.class, null));

        RealmIdentity elytronIdentity = realm.getRealmIdentity("elytron", null, null);
        assertEquals("ClearPassword", SupportLevel.SUPPORTED, elytronIdentity.getCredentialAcquireSupport(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR));
        assertEquals("DigestPassword", SupportLevel.SUPPORTED, elytronIdentity.getCredentialAcquireSupport(PasswordCredential.class, DigestPassword.ALGORITHM_DIGEST_MD5));
        assertEquals("Verify", SupportLevel.SUPPORTED, elytronIdentity.getEvidenceVerifySupport(PasswordGuessEvidence.class, null));

        ClearPassword elytronClear = elytronIdentity.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR).getPassword(ClearPassword.class);
        assertNotNull(elytronClear);
        assertEquals(ELYTRON_PASSWORD_CLEAR, new String(elytronClear.getPassword()));

        DigestPassword elytronDigest = elytronIdentity.getCredential(PasswordCredential.class, DigestPassword.ALGORITHM_DIGEST_MD5).getPassword(DigestPassword.class);
        assertNotNull(elytronDigest);
        String actualHex = ByteIterator.ofBytes(elytronDigest.getDigest()).hexEncode().drainToString();
        assertEquals(ELYTRON_PASSWORD_HASH, actualHex);

        assertTrue(elytronIdentity.verifyEvidence(goodGuess));
        assertFalse(elytronIdentity.verifyEvidence(badGuess));

        elytronIdentity.dispose();

        RealmIdentity badIdentity = realm.getRealmIdentity("noone", null, null);
        assertEquals("ClearPassword", SupportLevel.UNSUPPORTED, badIdentity.getCredentialAcquireSupport(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR));
        assertEquals("DigestPassword", SupportLevel.UNSUPPORTED, badIdentity.getCredentialAcquireSupport(PasswordCredential.class, DigestPassword.ALGORITHM_DIGEST_MD5));
        assertEquals("Verify", SupportLevel.UNSUPPORTED, badIdentity.getEvidenceVerifySupport(PasswordGuessEvidence.class, null));

        assertNull(badIdentity.getCredential(Credential.class));

        assertFalse(badIdentity.verifyEvidence(goodGuess));
        assertFalse(badIdentity.verifyEvidence(badGuess));

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

        PasswordGuessEvidence goodGuess = new PasswordGuessEvidence(ELYTRON_PASSWORD_CLEAR.toCharArray());
        PasswordGuessEvidence badGuess = new PasswordGuessEvidence("I will hack you".toCharArray());

        assertEquals("ClearPassword", SupportLevel.UNSUPPORTED, realm.getCredentialAcquireSupport(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR));
        assertEquals("DigestPassword", SupportLevel.SUPPORTED, realm.getCredentialAcquireSupport(PasswordCredential.class, DigestPassword.ALGORITHM_DIGEST_MD5));
        assertEquals("Verify", SupportLevel.SUPPORTED, realm.getEvidenceVerifySupport(PasswordGuessEvidence.class, null));

        RealmIdentity elytronIdentity = realm.getRealmIdentity("elytron", null, null);
        assertEquals("ClearPassword", SupportLevel.UNSUPPORTED, elytronIdentity.getCredentialAcquireSupport(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR));
        assertEquals("DigestPassword", SupportLevel.SUPPORTED, elytronIdentity.getCredentialAcquireSupport(PasswordCredential.class, DigestPassword.ALGORITHM_DIGEST_MD5));
        assertEquals("Verify", SupportLevel.SUPPORTED, elytronIdentity.getEvidenceVerifySupport(PasswordGuessEvidence.class, null));

        assertNotNull(elytronIdentity.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR));

        DigestPassword elytronDigest = elytronIdentity.getCredential(PasswordCredential.class, DigestPassword.ALGORITHM_DIGEST_MD5).getPassword(DigestPassword.class);
        assertNotNull(elytronDigest);
        String actualHex = ByteIterator.ofBytes(elytronDigest.getDigest()).hexEncode().drainToString();
        assertEquals(ELYTRON_PASSWORD_HASH, actualHex);

        assertTrue(elytronIdentity.verifyEvidence(goodGuess));
        assertFalse(elytronIdentity.verifyEvidence(badGuess));

        elytronIdentity.dispose();

        RealmIdentity badIdentity = realm.getRealmIdentity("noone", null, null);
        assertEquals("ClearPassword", SupportLevel.UNSUPPORTED, badIdentity.getCredentialAcquireSupport(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR));
        assertEquals("DigestPassword", SupportLevel.UNSUPPORTED, badIdentity.getCredentialAcquireSupport(PasswordCredential.class, DigestPassword.ALGORITHM_DIGEST_MD5));
        assertEquals("Verify", SupportLevel.UNSUPPORTED, badIdentity.getEvidenceVerifySupport(PasswordGuessEvidence.class, null));

        assertNull(badIdentity.getCredential(Credential.class));
        assertNull(badIdentity.getCredential(Credential.class));

        assertFalse(badIdentity.verifyEvidence(goodGuess));
        assertFalse(badIdentity.verifyEvidence(badGuess));

        badIdentity.dispose();
    }
}
