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
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.spec.OneTimePasswordSpec;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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
        performSimpleNameTest("plainUser", "userPassword-clear", ClearPassword.ALGORITHM_CLEAR, "plainPassword".toCharArray());
    }

    @Test
    public void testMd5User() throws Exception {
        performSimpleNameTest("md5User", "userPassword-md5", SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5,
                "md5Password".toCharArray());
    }

    @Test
    public void testSmd5User() throws Exception {
        performSimpleNameTest("smd5User", "userPassword-smd5", SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5, "smd5Password".toCharArray());
    }

    @Test
    public void testSha512User() throws Exception {
        performSimpleNameTest("sha512User", "userPassword-sha512", SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512, "sha512Password".toCharArray());
    }

    @Test
    public void testSsha512User() throws Exception {
        performSimpleNameTest("ssha512User", "userPassword-ssha512", SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, "ssha512Password".toCharArray());
    }

    @Test
    public void testCryptUser() throws Exception {
        performSimpleNameTest("cryptUser", "userPassword-crypt", UnixDESCryptPassword.ALGORITHM_CRYPT_DES, "cryptIt".toCharArray());
    }

    @Test
    public void testCryptUserLongPassword() throws Exception {
        performSimpleNameTest("cryptUserLong", "userPassword-crypt", UnixDESCryptPassword.ALGORITHM_CRYPT_DES, "cryptPassword".toCharArray());
    }

    @Test
    public void testBsdCryptUser() throws Exception {
        performSimpleNameTest("bsdCryptUser", "userPassword-crypt_", BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES, "cryptPassword".toCharArray());
    }

    @Test
    public void testOneTimePasswordUser0() throws Exception {
        CredentialSupport support = simpleToDnRealm.getCredentialSupport("otp");
        assertEquals("Pre identity", CredentialSupport.UNKNOWN, support);

        RealmIdentity identity = simpleToDnRealm.createRealmIdentity("userWithOtp");
        verifyPasswordSupport(identity, "otp", CredentialSupport.FULLY_SUPPORTED);

        OneTimePassword otp = (OneTimePassword) identity.getCredential("otp", PasswordCredential.class).getPassword();
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

        assertEquals(CredentialSupport.UNKNOWN, simpleToDnRealm.getCredentialSupport("otp"));
        assertEquals(CredentialSupport.FULLY_SUPPORTED, identity.getCredentialSupport("otp"));

        identity.setCredential("otp", new PasswordCredential(password));

        ModifiableRealmIdentity newIdentity = (ModifiableRealmIdentity) simpleToDnRealm.createRealmIdentity("userWithOtp");
        assertNotNull(newIdentity);

        verifyPasswordSupport(newIdentity, "otp", CredentialSupport.FULLY_SUPPORTED);

        OneTimePassword otp = (OneTimePassword) newIdentity.getCredential("otp", PasswordCredential.class).getPassword();
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

        identity.setCredentials(Collections.EMPTY_MAP);
        identity.setCredentials(Collections.EMPTY_MAP); // double clearing should not fail

        Map<String, Credential> credentials = new HashMap<>();
        credentials.put("otp", new PasswordCredential(password));
        identity.setCredentials(credentials);

        ModifiableRealmIdentity newIdentity = (ModifiableRealmIdentity) simpleToDnRealm.createRealmIdentity("userWithOtp");
        assertNotNull(newIdentity);

        verifyPasswordSupport(newIdentity, "otp", CredentialSupport.FULLY_SUPPORTED);

        OneTimePassword otp = (OneTimePassword) newIdentity.getCredential("otp", PasswordCredential.class).getPassword();
        assertNotNull(otp);
        assertEquals(65, otp.getSequenceNumber());
        Assert.assertArrayEquals(new byte[] { 'o', 'p', 'q' }, otp.getHash());
        Assert.assertArrayEquals(new byte[] { 'r', 's', 't' }, otp.getSeed());
    }

    private void performSimpleNameTest(String simpleName, String credentialName, String algorithm, char[] password) throws NoSuchAlgorithmException, InvalidKeyException, RealmUnavailableException {
        RealmIdentity realmIdentity = simpleToDnRealm.createRealmIdentity(simpleName);
        CredentialSupport support = simpleToDnRealm.getCredentialSupport(credentialName);
        assertEquals("Pre identity", CredentialSupport.UNKNOWN, support);

        verifyPasswordSupport(realmIdentity, credentialName, CredentialSupport.FULLY_SUPPORTED);
        verifyPassword(realmIdentity, credentialName, algorithm, password);
    }

    private void verifyPasswordSupport(RealmIdentity identity, String credentialName, CredentialSupport requiredSupport) throws RealmUnavailableException {
        CredentialSupport credentialSupport = identity.getCredentialSupport(credentialName);
        assertEquals("Identity level support", requiredSupport, credentialSupport);
    }

    private void verifyPassword(RealmIdentity identity, String credentialName, String algorithm, char[] password) throws NoSuchAlgorithmException, InvalidKeyException, RealmUnavailableException {
        Password loadedPassword = identity.getCredential(credentialName, PasswordCredential.class).getPassword();

        PasswordFactory factory = PasswordFactory.getInstance(algorithm);
        final Password translated = factory.translate(loadedPassword);
        assertTrue("Valid Password", factory.verify(translated, password));
        assertFalse("Invalid Password", factory.verify(translated, "LetMeIn".toCharArray()));
    }
}
