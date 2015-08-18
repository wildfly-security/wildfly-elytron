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

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.OneTimePasswordSpec;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Test case to test access to passwords stored in LDAP using the 'userPassword' attribute.
 *
 * This test case use {@link DirContextFactoryRule} to ensure running embedded LDAP server.
 *
 * Note: Verify {@link TestEnvironmentTest} is working first before focusing on errors in this test case.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PasswordSupportTest {

    @ClassRule
    public static DirContextFactoryRule dirContextFactory = new DirContextFactoryRule();
    private static SecurityRealm simpleToDnRealm;

    @BeforeClass
    public static void createRealm() {
        simpleToDnRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory.create())
                .setPrincipalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                .setRdnIdentifier("uid")
                                .setOtpAttributes("otpAlgorithm","otpHash","otpSeed","otpSequence")
                                .build()
                )
                .build();
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
        performSimpleNameTest("md5User", SimpleDigestPassword.class, SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5,
                "md5Password".toCharArray());
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

    @Test
    public void testOneTimePasswordUser0() throws Exception {
        CredentialSupport support = simpleToDnRealm.getCredentialSupport(OneTimePassword.class, null);
        assertEquals("Pre identity", CredentialSupport.UNKNOWN, support);

        RealmIdentity identity = simpleToDnRealm.createRealmIdentity("userWithOtp");
        verifyPasswordSupport(identity, OneTimePassword.class);

        OneTimePassword otp = identity.getCredential(OneTimePassword.class, "otp-sha1");
        assertNotNull(otp);
        assertEquals(1234, otp.getSequenceNumber());
        Assert.assertArrayEquals(new byte[] { 'a', 'b', 'c', 'd' }, otp.getHash());
        Assert.assertArrayEquals(new byte[] { 'e', 'f', 'g', 'h' }, otp.getSeed());
    }

    @Test
    public void testOneTimePasswordUser1Update() throws Exception {
        OneTimePasswordSpec spec = new OneTimePasswordSpec(new byte[] { 'i', 'j', 'k' }, new byte[] { 'l', 'm', 'n' }, 4321);
        final PasswordFactory passwordFactory = PasswordFactory.getInstance("otp-sha1");
        final OneTimePassword password = (OneTimePassword) passwordFactory.generatePassword(spec);
        assertNotNull(password);

        ModifiableRealmIdentity identity = (ModifiableRealmIdentity) simpleToDnRealm.createRealmIdentity("userWithOtp");
        assertNotNull(identity);

        assertEquals(CredentialSupport.UNKNOWN, simpleToDnRealm.getCredentialSupport(OneTimePassword.class, "otp-sha1"));
        assertEquals(CredentialSupport.FULLY_SUPPORTED, identity.getCredentialSupport(OneTimePassword.class, "otp-sha1"));

        identity.setCredential(password);

        ModifiableRealmIdentity newIdentity = (ModifiableRealmIdentity) simpleToDnRealm.createRealmIdentity("userWithOtp");
        assertNotNull(newIdentity);

        verifyPasswordSupport(newIdentity, OneTimePassword.class);

        OneTimePassword otp = newIdentity.getCredential(OneTimePassword.class, "otp-sha1");
        assertNotNull(otp);
        assertEquals(4321, otp.getSequenceNumber());
        Assert.assertArrayEquals(new byte[] { 'i', 'j', 'k' }, otp.getHash());
        Assert.assertArrayEquals(new byte[] { 'l', 'm', 'n' }, otp.getSeed());
    }

    @Test
    public void testOneTimePasswordUser2SetCredentials() throws Exception {
        OneTimePasswordSpec spec = new OneTimePasswordSpec(new byte[] { 'o', 'p', 'q' }, new byte[] { 'r', 's', 't' }, 65);
        final PasswordFactory passwordFactory = PasswordFactory.getInstance("otp-sha1");
        final OneTimePassword password = (OneTimePassword) passwordFactory.generatePassword(spec);
        assertNotNull(password);

        ModifiableRealmIdentity identity = (ModifiableRealmIdentity) simpleToDnRealm.createRealmIdentity("userWithOtp");
        assertNotNull(identity);

        identity.setCredentials(Collections.EMPTY_LIST);
        identity.setCredentials(Collections.EMPTY_LIST); // double clearing should not fail

        List<Object> credentials = new LinkedList<>();
        credentials.add(password);
        identity.setCredentials(credentials);

        ModifiableRealmIdentity newIdentity = (ModifiableRealmIdentity) simpleToDnRealm.createRealmIdentity("userWithOtp");
        assertNotNull(newIdentity);

        verifyPasswordSupport(newIdentity, OneTimePassword.class);

        OneTimePassword otp = newIdentity.getCredential(OneTimePassword.class, "otp-sha1");
        assertNotNull(otp);
        assertEquals(65, otp.getSequenceNumber());
        Assert.assertArrayEquals(new byte[] { 'o', 'p', 'q' }, otp.getHash());
        Assert.assertArrayEquals(new byte[] { 'r', 's', 't' }, otp.getSeed());
    }

    private void performSimpleNameTest(String simpleName, Class<?> credentialType, String algorithm, char[] password) throws NoSuchAlgorithmException, InvalidKeyException, RealmUnavailableException {
        RealmIdentity realmIdentity = simpleToDnRealm.createRealmIdentity(simpleName);
        CredentialSupport support = simpleToDnRealm.getCredentialSupport(credentialType, null);
        assertEquals("Pre identity", CredentialSupport.UNKNOWN, support);

        verifyPasswordSupport(realmIdentity, credentialType);
        verifyPassword(realmIdentity, credentialType, algorithm, password);
    }

    private void verifyPasswordSupport(RealmIdentity identity, Class<?> credentialType) throws RealmUnavailableException {
        CredentialSupport credentialSupport = identity.getCredentialSupport(credentialType, null);
        assertEquals("Identity level support", CredentialSupport.FULLY_SUPPORTED, credentialSupport);
    }

    private void verifyPassword(RealmIdentity identity, Class<?> credentialType, String algorithm, char[] password) throws NoSuchAlgorithmException, InvalidKeyException, RealmUnavailableException {
        Password loadedPassword = (Password) identity.getCredential(credentialType, null);

        PasswordFactory factory = PasswordFactory.getInstance(algorithm);
        final Password translated = factory.translate(loadedPassword);
        assertTrue("Valid Password", factory.verify(translated, password));
        assertFalse("Invalid Password", factory.verify(translated, "LetMeIn".toCharArray()));
    }
}
