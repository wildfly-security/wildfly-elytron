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

package org.wildfly.security.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.realm.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.interfaces.UnixMD5CryptPassword;

/**
 * Testsuite for the {@link org.wildfly.security.auth.realm.KeyStoreBackedSecurityRealm}.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class KeyStoreBackedSecurityRealmTest {

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
    public void testPasswordFileKeyStore() throws Exception {
        // initialize the keystore, this time loading the users from a password file.
        final InputStream stream = this.getClass().getResourceAsStream("passwd");
        final KeyStore keyStore = KeyStore.getInstance("PasswordFile");
        keyStore.load(stream, null);
        assertEquals("Invalid number of keystore entries", 2, keyStore.size());

        // create a realm identity that represents the user "elytron" (password is of type MD5Crypt)
        SecurityRealm realm = new KeyStoreBackedSecurityRealm(keyStore);
        RealmIdentity realmIdentity = realm.getRealmIdentity("elytron", null, null);

        // only the Password type credential type is supported in the password file keystore.
        assertEquals("Invalid credential support", SupportLevel.SUPPORTED, realmIdentity.getCredentialAcquireSupport(PasswordCredential.class, UnixMD5CryptPassword.ALGORITHM_CRYPT_MD5));
        assertEquals("Invalid credential support", SupportLevel.UNSUPPORTED, realmIdentity.getCredentialAcquireSupport(PasswordCredential.class, BCryptPassword.ALGORITHM_BCRYPT));

        // as a result, the only type that will yield a non null credential is Password.
        Password password = realmIdentity.getCredential(PasswordCredential.class, null).getPassword();
        assertNotNull("Invalid null password", password);
        assertTrue("Invalid password type", password instanceof UnixMD5CryptPassword);

        // the realm identity must be able to verify the password for the user "elytron".
        assertTrue("Error validating credential", realmIdentity.verifyEvidence(new PasswordGuessEvidence("passwd12#$".toCharArray())));
        assertFalse("Error validating credential", realmIdentity.verifyEvidence(new PasswordGuessEvidence("wrongpass".toCharArray())));

        // now create a realm identity that represents the user "javajoe" (password is of type BCrypt).
        realmIdentity = realm.getRealmIdentity("javajoe", null, null);

        // only the Password type credential type is supported in the password file keystore.
        assertEquals("Invalid credential support", SupportLevel.SUPPORTED, realmIdentity.getCredentialAcquireSupport(PasswordCredential.class, BCryptPassword.ALGORITHM_BCRYPT));
        assertEquals("Invalid credential support", SupportLevel.UNSUPPORTED, realmIdentity.getCredentialAcquireSupport(PasswordCredential.class, UnixMD5CryptPassword.ALGORITHM_CRYPT_MD5));

        // as a result, the only type that will yield a non null credential is Password.
        password = realmIdentity.getCredential(PasswordCredential.class, null).getPassword();
        assertNotNull("Invalid null password", password);
        assertTrue("Invalid password type", password instanceof BCryptPassword);

        // the realm identity must be able to verify the password for the user "javajoe".
        assertTrue("Error validating credential", realmIdentity.verifyEvidence(new PasswordGuessEvidence("$#21pass".toCharArray())));
        assertFalse("Error validating credential", realmIdentity.verifyEvidence(new PasswordGuessEvidence("wrongpass".toCharArray())));
    }
}
