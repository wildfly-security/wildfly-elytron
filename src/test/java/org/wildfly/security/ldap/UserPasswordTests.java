/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.provider.CredentialSupport;
import org.wildfly.security.auth.provider.RealmIdentity;
import org.wildfly.security.auth.provider.SecurityRealm;
import org.wildfly.security.auth.provider.ldap.DirContextFactory;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.provider.ldap.SimpleDirContextFactoryBuilder;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.TrivialDigestPassword;
import org.wildfly.security.password.spec.TrivialDigestPasswordSpec;

/**
 * Test case to test access to passwords stored in LDAP using the 'userPassword' attribute.
 *
 * Note: Verify {@link ConnectionTests} is working first before focusing on errors in this test case.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class UserPasswordTests {

    private static SecurityRealm simpleToDnRealm;
    private static SecurityRealm simpleToSimpleRealm;

    @BeforeClass
    public static void createRealm() {
        DirContextFactory dirContextFactory = SimpleDirContextFactoryBuilder.builder()
                .setProviderUrl(String.format("ldap://localhost:%d/", LdapTest.LDAP_PORT))
                .setSecurityPrincipal(LdapTest.SERVER_DN)
                .setSecurityCredential(LdapTest.SERVER_CREDENTIAL)
                .build();

        simpleToDnRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping()
                .setNameIsDn(false)
                .setPrincipalUseDn(true)
                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                .setNameAttribute("uid")
                .build()
                .userPassword()
                .addCredentialSupport(ClearPassword.class, CredentialSupport.POSSIBLY_SUPPORTED)
                .addCredentialSupport(TrivialDigestPassword.class, CredentialSupport.POSSIBLY_SUPPORTED)
                .build()
                .build();

        simpleToSimpleRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping()
                .setNameIsDn(false)
                .setPrincipalUseDn(false)
                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                .setNameAttribute("uid")
                .setReloadPrincipalName(true)
                .setValidatePresence(true)
                .build()
                .userPassword()
                .addCredentialSupport(ClearPassword.class, CredentialSupport.POSSIBLY_SUPPORTED)
                .addCredentialSupport(TrivialDigestPassword.class, CredentialSupport.POSSIBLY_SUPPORTED)
                .build()
                .build();
    }

    @AfterClass
    public static void removeRealm() {
        simpleToSimpleRealm = null;
        simpleToDnRealm = null;
    }

    @Test
    public void testPlainUser() throws Exception {
        performSimpleNameTest("plainUser", ClearPassword.class, ClearPassword.ALGORITHM_CLEAR, "plainPassword".toCharArray());
    }

    @Test
    public void testSha512User() throws Exception {
        performSimpleNameTest("sha512User", TrivialDigestPassword.class, TrivialDigestPassword.ALGORITHM_DIGEST_SHA_512, "sha512Password".toCharArray());
    }

    @Test
    public void testSsha512User() throws Exception {
        performSimpleNameTest("ssha512User", TrivialDigestPassword.class, TrivialDigestPassword.ALGORITHM_DIGEST_SHA_512, "ssha512Password".toCharArray());
    }

    @Test
    public void testCryptUser() throws Exception {
        performSimpleNameTest("cryptUser", ClearPassword.class, ClearPassword.ALGORITHM_CLEAR, "cryptPassword".toCharArray());
    }

    private void performSimpleNameTest(String simpleName, Class<?> credentialType, String algorithm, char[] password) throws NoSuchAlgorithmException, InvalidKeyException {
        RealmIdentity realmIdentity = simpleToDnRealm.createRealmIdentity(simpleName);
        CredentialSupport support = simpleToDnRealm.getCredentialSupport(credentialType);
        assertEquals("Pre identity", CredentialSupport.POSSIBLY_SUPPORTED, support);

        verifyPasswordSupport(realmIdentity, credentialType);
        verifyPassword(realmIdentity, credentialType, algorithm, password);
    }

    private void verifyPasswordSupport(RealmIdentity identity, Class<?> credentialType) {
        CredentialSupport credentialSupport = identity.getCredentialSupport(credentialType);
        assertEquals("Identity level support", CredentialSupport.SUPPORTED, credentialSupport);
    }

    private void verifyPassword(RealmIdentity identity, Class<?> credentialType, String algorithm, char[] password) throws NoSuchAlgorithmException, InvalidKeyException {
        Password loadedPassword = (Password) identity.getCredential(credentialType);

        PasswordFactory factory = PasswordFactory.getInstance(algorithm);
        assertTrue("Valid Password", factory.verify(loadedPassword, password));
        assertFalse("Invalid Password", factory.verify(loadedPassword, "LetMeIn".toCharArray()));
    }

}
