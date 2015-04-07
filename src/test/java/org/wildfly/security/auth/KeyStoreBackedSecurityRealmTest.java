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

import static org.junit.Assert.*;

import javax.security.auth.Subject;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.provider.CredentialSupport;
import org.wildfly.security.auth.provider.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.provider.RealmIdentity;
import org.wildfly.security.auth.provider.SecurityRealm;
import org.wildfly.security.keystore.EnablingPasswordEntry;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.interfaces.UnixMD5CryptPassword;

/**
 * Testsuite for the {@link org.wildfly.security.auth.provider.KeyStoreBackedSecurityRealm}.
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
    public void testBasicRealmAPI() throws Exception {

        // instantiate and initialize an empty properties-based keystore.
        final KeyStore keyStore = KeyStore.getInstance("PropertiesFile");
        keyStore.load(new InputStream() {
            public int read() throws IOException {
                return -1;
            }
        }, null);

        // basic realm identity testing using the empty keystore.
        SecurityRealm realm = new KeyStoreBackedSecurityRealm(keyStore);
        RealmIdentity realmIdentity = realm.createRealmIdentity("javaduke");
        assertNotNull("Unexpected null realm identity", realmIdentity);
        Principal realmPrincipal = realmIdentity.getPrincipal();
        assertNotNull("Unexpecteed null realm principal", realmPrincipal);
        assertTrue("Invalid realm principal type", realmPrincipal instanceof NamePrincipal);
        assertEquals("Invalid realm principal name", "javaduke", realmPrincipal.getName());

        // there is no keystore entry matching the test principal - getCredentialSupport must return UNSUPPORTED and getCredential must return null.
        assertEquals("Invalid credential support", CredentialSupport.UNSUPPORTED, realmIdentity.getCredentialSupport(Password.class));
        assertNull("Invalid credential", realmIdentity.getCredential(Password.class));

        // there is no keystore entry matching the test principal - verifyCredential must fail as there is no verifiable entry.
        assertFalse(realmIdentity.verifyCredential("dukepass!@34".toCharArray()));

        // create another realm identity, this time using the variant that takes a principal.
        Principal principal = new NamePrincipal("javajoe");
        realmIdentity = realm.createRealmIdentity(principal);
        assertSame(principal, realmIdentity.getPrincipal());
        try {
            realmIdentity = realm.createRealmIdentity(new Principal() {
                @Override
                public String getName() {
                    return "elytron";
                }

                @Override
                public boolean implies(Subject subject) {
                    return false;
                }
            });
            fail("Invalid principal type should have been rejected");
        } catch (IllegalArgumentException ile) {
        }
    }

    @Test
    public void testPropertiesFileKeyStore() throws Exception {
        // initialize the keystore, this time loading the users from a test properties file.
        final InputStream stream = this.getClass().getResourceAsStream("users.properties");
        final KeyStore keyStore = KeyStore.getInstance("PropertiesFile");
        keyStore.load(stream, null);
        assertEquals("Invalid number of keystore entries", 2, keyStore.size());

        // create a realm identity that represents the enabled user "elytron".
        SecurityRealm realm = new KeyStoreBackedSecurityRealm(keyStore);
        RealmIdentity realmIdentity = realm.createRealmIdentity("elytron");

        // only the Password type credential type is supported in the properties-based keystore.
        assertEquals("Invalid credential support", CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(Password.class));
        assertEquals("Invalid credential support", CredentialSupport.UNSUPPORTED, realmIdentity.getCredentialSupport(PrivateKey.class));
        assertEquals("Invalid credential support", CredentialSupport.UNSUPPORTED, realmIdentity.getCredentialSupport(Certificate.class));

        // as a result, the only type that will yield a non null credential is Password.
        Password password = realmIdentity.getCredential(Password.class);
        assertNotNull("Invalid null password", password);
        assertTrue("Invalid password type", password instanceof DigestPassword);
        DigestPassword digestPassword = (DigestPassword) password;
        assertEquals("Invalid digest realm", "ManagementRealm", digestPassword.getRealm());
        assertEquals("Invliad digest username", "elytron", digestPassword.getUsername());

        // other types must result in a null credential.
        assertNull("Invalid non null password", realmIdentity.getCredential(PrivateKey.class));
        assertNull("Invalid non null password", realmIdentity.getCredential(Certificate.class));

        // the realm identity must be able to verify the password for an enabled user.
        assertTrue("Error validating credential", realmIdentity.verifyCredential("passwd12#$".toCharArray()));
        assertFalse("Error validating credential", realmIdentity.verifyCredential("wrongpass".toCharArray()));

        // now lets switch to a realm identity that represents the disabled user "javajoe".
        realmIdentity = realm.createRealmIdentity("javajoe");

        // a disabled identity doesn't support any credential types - it acts as if the entry didn't exist.
        assertEquals("Invalid credential support", CredentialSupport.UNSUPPORTED, realmIdentity.getCredentialSupport(Password.class));
        assertEquals("Invalid credential support", CredentialSupport.UNSUPPORTED, realmIdentity.getCredentialSupport(PrivateKey.class));
        assertEquals("Invalid credential support", CredentialSupport.UNSUPPORTED, realmIdentity.getCredentialSupport(Certificate.class));

        // as a result, none of the types will yield a non null credential.
        assertNull("Invalid non null password", realmIdentity.getCredential(Password.class));
        assertNull("Invalid non null password", realmIdentity.getCredential(PrivateKey.class));
        assertNull("Invalid non null password", realmIdentity.getCredential(Certificate.class));

        // and the realm identity won't be able to verify the password of the entry.
        assertFalse("Error validating credential", realmIdentity.verifyCredential("$#21pass".toCharArray()));
        assertFalse("Error validating credential", realmIdentity.verifyCredential("wrongpass".toCharArray()));

        // now we re-enable javajoe using the keystore API and rerun the previous tests.
        ((EnablingPasswordEntry) keyStore.getEntry("javajoe", null)).enable();
        assertEquals("Invalid credential support", CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(Password.class));
        assertNotNull("Invalid null credential", realmIdentity.getCredential(Password.class));
        assertTrue("Error validating credential", realmIdentity.verifyCredential("$#21pass".toCharArray()));
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
        RealmIdentity realmIdentity = realm.createRealmIdentity("elytron");

        // only the Password type credential type is supported in the password file keystore.
        assertEquals("Invalid credential support", CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(Password.class));
        assertEquals("Invalid credential support", CredentialSupport.UNSUPPORTED, realmIdentity.getCredentialSupport(PrivateKey.class));
        assertEquals("Invalid credential support", CredentialSupport.UNSUPPORTED, realmIdentity.getCredentialSupport(Certificate.class));

        // as a result, the only type that will yield a non null credential is Password.
        Password password = realmIdentity.getCredential(Password.class);
        assertNotNull("Invalid null password", password);
        assertTrue("Invalid password type", password instanceof UnixMD5CryptPassword);

        // other types must result in a null credential.
        assertNull("Invalid non null password", realmIdentity.getCredential(PrivateKey.class));
        assertNull("Invalid non null password", realmIdentity.getCredential(Certificate.class));

        // the realm identity must be able to verify the password for the user "elytron".
        assertTrue("Error validating credential", realmIdentity.verifyCredential("passwd12#$".toCharArray()));
        assertFalse("Error validating credential", realmIdentity.verifyCredential("wrongpass".toCharArray()));

        // now create a realm identity that represents the user "javajoe" (password is of type BCrypt).
        realmIdentity = realm.createRealmIdentity("javajoe");

        // only the Password type credential type is supported in the password file keystore.
        assertEquals("Invalid credential support", CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(Password.class));
        assertEquals("Invalid credential support", CredentialSupport.UNSUPPORTED, realmIdentity.getCredentialSupport(PrivateKey.class));
        assertEquals("Invalid credential support", CredentialSupport.UNSUPPORTED, realmIdentity.getCredentialSupport(Certificate.class));

        // as a result, the only type that will yield a non null credential is Password.
        password = realmIdentity.getCredential(Password.class);
        assertNotNull("Invalid null password", password);
        assertTrue("Invalid password type", password instanceof BCryptPassword);

        // other types must result in a null credential.
        assertNull("Invalid non null password", realmIdentity.getCredential(PrivateKey.class));
        assertNull("Invalid non null password", realmIdentity.getCredential(Certificate.class));

        // the realm identity must be able to verify the password for the user "javajoe".
        assertTrue("Error validating credential", realmIdentity.verifyCredential("$#21pass".toCharArray()));
        assertFalse("Error validating credential", realmIdentity.verifyCredential("wrongpass".toCharArray()));
    }
}
