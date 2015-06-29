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

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.provider.ldap.DirContextFactory;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.provider.ldap.SimpleDirContextFactoryBuilder;
import org.wildfly.security.auth.spi.CredentialSupport;
import org.wildfly.security.auth.spi.RealmIdentity;
import org.wildfly.security.auth.spi.RealmUnavailableException;
import org.wildfly.security.auth.spi.SecurityRealm;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Test case to test access to passwords stored in LDAP using the 'userPassword' attribute.
 *
 * As a test case it is indented this is only executed as part of the {@link LdapTestSuite} so that the required LDAP server is running.
 *
 * Note: Verify {@link ConnectionSuiteChild} is working first before focusing on errors in this test case.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class UserPasswordSuiteChild {

    private static SecurityRealm simpleToDnRealm;

    @BeforeClass
    public static void createRealm() {
        DirContextFactory dirContextFactory = SimpleDirContextFactoryBuilder.builder()
                .setProviderUrl(String.format("ldap://localhost:%d/", LdapTestSuite.LDAP_PORT))
                .setSecurityPrincipal(LdapTestSuite.SERVER_DN)
                .setSecurityCredential(LdapTestSuite.SERVER_CREDENTIAL)
                .build();

        simpleToDnRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                    .useX500Principal()
                    .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                    .setNameAttribute("uid")
                    .build()
                )
                .build();
    }

    @AfterClass
    public static void removeRealm() {
        simpleToDnRealm = null;
    }

    @Test
    public void testPlainUser() throws Exception {
        performSimpleNameTest("plainUser", ClearPassword.class, ClearPassword.ALGORITHM_CLEAR, "plainPassword".toCharArray());
    }

    @Test
    public void testPlainUserVerifyOnRealmIdentity() throws Exception {
        RealmIdentity realmIdentity = simpleToDnRealm.createRealmIdentity("plainUser");
        ClearPasswordSpec passwordSpec = new ClearPasswordSpec("plainPassword".toCharArray());
        PasswordFactory instance = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        Password password = instance.generatePassword(passwordSpec);

        verifyPasswordSupport(realmIdentity, ClearPassword.class);
        assertTrue(realmIdentity.verifyCredential(password));
    }

    @Test
    public void testPlainUserVerifyFailedOnRealmIdentity() throws Exception {
        RealmIdentity realmIdentity = simpleToDnRealm.createRealmIdentity("plainUser");
        ClearPasswordSpec invalidPasswordSpec = new ClearPasswordSpec("invalidPassword".toCharArray());
        PasswordFactory instance = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        Password invalidPassword = instance.generatePassword(invalidPasswordSpec);

        verifyPasswordSupport(realmIdentity, ClearPassword.class);
        assertFalse(realmIdentity.verifyCredential(invalidPassword));
    }

    @Test
    public void testMd5User() throws Exception {
        performSimpleNameTest("md5User", SimpleDigestPassword.class, SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5, "md5Password".toCharArray());
    }

    @Test
    public void testSmd5User() throws Exception {
        performSimpleNameTest("smd5User", SaltedSimpleDigestPassword.class, SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5, "smd5Password".toCharArray());
    }

    @Test
    public void testSha512User() throws Exception {
        performSimpleNameTest("sha512User", SimpleDigestPassword.class, SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512, "sha512Password".toCharArray());
    }

    @Test
    public void testSsha512User() throws Exception {
        performSimpleNameTest("ssha512User", SaltedSimpleDigestPassword.class, SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, "ssha512Password".toCharArray());
    }

    @Test
    public void testCryptUser() throws Exception {
        performSimpleNameTest("cryptUser", UnixDESCryptPassword.class, UnixDESCryptPassword.ALGORITHM_CRYPT_DES, "cryptIt".toCharArray());
    }

    @Test
    public void testCryptUserLongPassword() throws Exception {
        performSimpleNameTest("cryptUserLong", UnixDESCryptPassword.class, UnixDESCryptPassword.ALGORITHM_CRYPT_DES, "cryptPassword".toCharArray());
    }

    @Test
    public void testBsdCryptUser() throws Exception {
        performSimpleNameTest("bsdCryptUser", BSDUnixDESCryptPassword.class, BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES, "cryptPassword".toCharArray());
    }

    private void performSimpleNameTest(String simpleName, Class<?> credentialType, String algorithm, char[] password) throws NoSuchAlgorithmException, InvalidKeyException, RealmUnavailableException {
        RealmIdentity realmIdentity = simpleToDnRealm.createRealmIdentity(simpleName);
        CredentialSupport support = simpleToDnRealm.getCredentialSupport(credentialType);
        assertEquals("Pre identity", CredentialSupport.UNKNOWN, support);

        verifyPasswordSupport(realmIdentity, credentialType);
        verifyPassword(realmIdentity, credentialType, algorithm, password);
    }

    private void verifyPasswordSupport(RealmIdentity identity, Class<?> credentialType) throws RealmUnavailableException {
        CredentialSupport credentialSupport = identity.getCredentialSupport(credentialType);
        assertEquals("Identity level support", CredentialSupport.FULLY_SUPPORTED, credentialSupport);
    }

    private void verifyPassword(RealmIdentity identity, Class<?> credentialType, String algorithm, char[] password) throws NoSuchAlgorithmException, InvalidKeyException, RealmUnavailableException {
        Password loadedPassword = (Password) identity.getCredential(credentialType);

        PasswordFactory factory = PasswordFactory.getInstance(algorithm);
        final Password translated = factory.translate(loadedPassword);
        assertTrue("Valid Password", factory.verify(translated, password));
        assertFalse("Invalid Password", factory.verify(translated, "LetMeIn".toCharArray()));
    }

}
