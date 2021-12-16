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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.auth.server.ServerUtils.ELYTRON_PASSWORD_PROVIDERS;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.Encoding;
import org.wildfly.security.password.spec.OneTimePasswordSpec;

/**
 * Test case to test access to passwords stored in LDAP using the 'userPassword' attribute.
 *
 * This test case use {@link DirContextFactoryRule} to ensure running embedded LDAP server.
 *
 * Note: Verify {@link TestEnvironmentSuiteChild} is working first before focusing on errors in this test case.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PasswordSupportSuiteChild {

    private static SecurityRealm simpleToDnRealm;
    private static SecurityRealm charsetDnRealm;
    private static SecurityRealm encodingDnRealm;

    @BeforeClass
    public static void createRealm() {
        simpleToDnRealm = LdapSecurityRealmBuilder.builder()
            .setProviders(ELYTRON_PASSWORD_PROVIDERS)
            .setDirContextSupplier(LdapTestSuite.dirContextFactory.create())
            .identityMapping()
                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                .setRdnIdentifier("uid")
                .build()
            .userPasswordCredentialLoader()
                .enablePersistence()
                .build()
            .otpCredentialLoader()
                .setOtpAlgorithmAttribute("otpAlgorithm")
                .setOtpHashAttribute("otpHash")
                .setOtpSeedAttribute("otpSeed")
                .setOtpSequenceAttribute("otpSequence")
                .build()
            .build();

        charsetDnRealm = LdapSecurityRealmBuilder.builder()
                .setProviders(ELYTRON_PASSWORD_PROVIDERS)
                .setDirContextSupplier(LdapTestSuite.dirContextFactory.create())
                .setHashCharset(Charset.forName("gb2312"))
                .identityMapping()
                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                .setRdnIdentifier("uid")
                .build()
                .userPasswordCredentialLoader()
                .enablePersistence()
                .build()
                .otpCredentialLoader()
                .setOtpAlgorithmAttribute("otpAlgorithm")
                .setOtpHashAttribute("otpHash")
                .setOtpSeedAttribute("otpSeed")
                .setOtpSequenceAttribute("otpSequence")
                .build()
                .build();

        encodingDnRealm = LdapSecurityRealmBuilder.builder()
                .setProviders(ELYTRON_PASSWORD_PROVIDERS)
                .setDirContextSupplier(LdapTestSuite.dirContextFactory.create())
                .setHashEncoding(Encoding.HEX)
                .setHashCharset(Charset.forName("gb2312"))
                .identityMapping()
                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                .setRdnIdentifier("uid")
                .build()
                .userPasswordCredentialLoader()
                .enablePersistence()
                .build()
                .otpCredentialLoader()
                .setOtpAlgorithmAttribute("otpAlgorithm")
                .setOtpHashAttribute("otpHash")
                .setOtpSeedAttribute("otpSeed")
                .setOtpSequenceAttribute("otpSequence")
                .build()
                .build();
    }

    @Test
    public void testPlainUser() throws Exception {
        performSimpleNameTest("plainUser", ClearPassword.ALGORITHM_CLEAR, "plainPassword".toCharArray());
    }

    @Test
    public void testMd5User() throws Exception {
        performSimpleNameTest("md5User", SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5,
                "md5Password".toCharArray());
    }

    @Test
    public void testMd5UserWithCharset() throws Exception {
        performSimpleNameTest("md5UserCharset", SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5,
                "password密码".toCharArray(), Charset.forName("gb2312"), charsetDnRealm);

    }

    @Test
    public void testMd5UserWithCharsetAndHexEncoding() throws Exception {
        performSimpleNameTest("md5UserCharsetHex", SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5,
                "password密码".toCharArray(), Charset.forName("gb2312"), encodingDnRealm);

    }

    @Test
    public void testSmd5User() throws Exception {
        performSimpleNameTest("smd5User", SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5, "smd5Password".toCharArray());
    }

    @Test
    public void testSmd5UserWithCharset() throws Exception {
        performSimpleNameTest("smd5UserCharset", SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5, "password密码".toCharArray(),
                Charset.forName("gb2312"), charsetDnRealm);
    }

    @Test
    public void testSmd5UserWithCharsetAndHexEncoded() throws Exception {
        performSimpleNameTest("smd5UserCharsetHex", SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5, "password密码".toCharArray(),
                Charset.forName("gb2312"), encodingDnRealm);
    }

    @Test
    public void testSha512User() throws Exception {
        performSimpleNameTest("sha512User", SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512, "sha512Password".toCharArray());
    }

    @Test
    public void testSha512UserWithCharset() throws Exception {
        performSimpleNameTest("sha512UserCharset", SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512, "password密码".toCharArray(),
                Charset.forName("gb2312"), charsetDnRealm);
    }

    @Test
    public void testSha512UserWithCharsetAndHexEncoded() throws Exception {
        performSimpleNameTest("sha512UserCharsetHex", SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512, "password密码".toCharArray(),
                Charset.forName("gb2312"), encodingDnRealm);
    }

    @Test
    public void testSsha512User() throws Exception {
        performSimpleNameTest("ssha512User", SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, "ssha512Password".toCharArray());
    }

    @Test
    public void testSsha512UserWithCharset() throws Exception {
        performSimpleNameTest("ssha512UserCharset", SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, "password密码".toCharArray(),
                Charset.forName("gb2312"), charsetDnRealm);
    }

    @Test
    public void testSsha512UserWithCharsetAndHexEncoded() throws Exception {
        performSimpleNameTest("ssha512UserCharsetHex", SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, "password密码".toCharArray(),
                Charset.forName("gb2312"), encodingDnRealm);
    }

    @Test
    public void testCryptUser() throws Exception {
        performSimpleNameTest("cryptUser", UnixDESCryptPassword.ALGORITHM_CRYPT_DES, "cryptIt".toCharArray());
    }

    @Test
    public void testCryptUserWithCharset() throws Exception {
        performSimpleNameTest("cryptUserCharset", UnixDESCryptPassword.ALGORITHM_CRYPT_DES, "password密码".toCharArray(),
                Charset.forName("gb2312"), charsetDnRealm);
    }

    @Test
    public void testCryptUserLongPassword() throws Exception {
        performSimpleNameTest("cryptUserLong", UnixDESCryptPassword.ALGORITHM_CRYPT_DES, "cryptPassword".toCharArray());
    }

    @Test
    public void testBsdCryptUser() throws Exception {
        performSimpleNameTest("bsdCryptUser", BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES, "cryptPassword".toCharArray());
    }

    @Test
    public void testBsdCryptUserWithCharset() throws Exception {
        performSimpleNameTest("bsdCryptUserCharset", BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES, "password密码".toCharArray(),
                Charset.forName("gb2312"), charsetDnRealm);
    }

    @Test
    public void testBsdCryptUserBinary() throws Exception {
        performSimpleNameTest("bsdCryptUser_binary", BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES, "cryptPassword".toCharArray());
    }

    @Test
    public void testOneTimePasswordUser0() throws Exception {
        SupportLevel support = simpleToDnRealm.getCredentialAcquireSupport(PasswordCredential.class, null, null);
        assertEquals("Pre identity", SupportLevel.SUPPORTED, support);

        RealmIdentity identity = simpleToDnRealm.getRealmIdentity(new NamePrincipal("userWithOtp"));
        verifyPasswordSupport(identity, OneTimePassword.ALGORITHM_OTP_SHA1, SupportLevel.SUPPORTED);

        OneTimePassword otp = identity.getCredential(PasswordCredential.class, OneTimePassword.ALGORITHM_OTP_SHA1).getPassword(OneTimePassword.class);
        assertNotNull(otp);
        assertEquals(1234, otp.getSequenceNumber());
        Assert.assertArrayEquals(new byte[] { 'a', 'b', 'c', 'd' }, otp.getHash());
        Assert.assertEquals("efgh", otp.getSeed());
    }

    @Test
    public void testOneTimePasswordUser1Update() throws Exception {
        OneTimePasswordSpec spec = new OneTimePasswordSpec(new byte[] { 'i', 'j', 'k' }, "lmn", 4321);
        final PasswordFactory passwordFactory = PasswordFactory.getInstance("otp-sha1", WildFlyElytronPasswordProvider.getInstance());
        final OneTimePassword password = (OneTimePassword) passwordFactory.generatePassword(spec);
        assertNotNull(password);

        ModifiableRealmIdentity identity = (ModifiableRealmIdentity) simpleToDnRealm.getRealmIdentity(new NamePrincipal("userWithOtp"));
        assertNotNull(identity);

        assertEquals(SupportLevel.POSSIBLY_SUPPORTED, simpleToDnRealm.getCredentialAcquireSupport(PasswordCredential.class, OneTimePassword.ALGORITHM_OTP_SHA1, null));
        assertEquals(SupportLevel.SUPPORTED, identity.getCredentialAcquireSupport(PasswordCredential.class, OneTimePassword.ALGORITHM_OTP_SHA1, null));

        identity.setCredentials(Collections.singleton(new PasswordCredential(password)));

        ModifiableRealmIdentity newIdentity = (ModifiableRealmIdentity) simpleToDnRealm.getRealmIdentity(new NamePrincipal("userWithOtp"));
        assertNotNull(newIdentity);

        verifyPasswordSupport(newIdentity, OneTimePassword.ALGORITHM_OTP_SHA1, SupportLevel.SUPPORTED);

        OneTimePassword otp = newIdentity.getCredential(PasswordCredential.class, OneTimePassword.ALGORITHM_OTP_SHA1).getPassword(OneTimePassword.class);
        assertNotNull(otp);
        assertEquals(4321, otp.getSequenceNumber());
        Assert.assertArrayEquals(new byte[] { 'i', 'j', 'k' }, otp.getHash());
        Assert.assertEquals("lmn", otp.getSeed());
    }

    @Test
    public void testOneTimePasswordUser2SetCredentials() throws Exception {
        OneTimePasswordSpec spec = new OneTimePasswordSpec(new byte[] { 'o', 'p', 'q' }, "rst", 65);
        final PasswordFactory passwordFactory = PasswordFactory.getInstance("otp-sha1", WildFlyElytronPasswordProvider.getInstance());
        final OneTimePassword password = (OneTimePassword) passwordFactory.generatePassword(spec);
        assertNotNull(password);

        ModifiableRealmIdentity identity = (ModifiableRealmIdentity) simpleToDnRealm.getRealmIdentity(new NamePrincipal("userWithOtp"));
        assertNotNull(identity);

        identity.setCredentials(Collections.emptyList());
        identity.setCredentials(Collections.emptyList()); // double clearing should not fail

        identity.setCredentials(Collections.singleton(new PasswordCredential(password)));

        ModifiableRealmIdentity newIdentity = (ModifiableRealmIdentity) simpleToDnRealm.getRealmIdentity(new NamePrincipal("userWithOtp"));
        assertNotNull(newIdentity);

        verifyPasswordSupport(newIdentity, OneTimePassword.ALGORITHM_OTP_SHA1, SupportLevel.SUPPORTED);

        OneTimePassword otp = newIdentity.getCredential(PasswordCredential.class, OneTimePassword.ALGORITHM_OTP_SHA1).getPassword(OneTimePassword.class);
        assertNotNull(otp);
        assertEquals(65, otp.getSequenceNumber());
        Assert.assertArrayEquals(new byte[] { 'o', 'p', 'q' }, otp.getHash());
        Assert.assertEquals("rst", otp.getSeed());
    }

    @Test
    public void testUserPasswordUserUpdate() throws Exception {

        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, WildFlyElytronPasswordProvider.getInstance());
        ClearPassword password = (ClearPassword) factory.generatePassword(new ClearPasswordSpec("createdPassword".toCharArray()));
        assertNotNull(password);

        ModifiableRealmIdentity identity = (ModifiableRealmIdentity) simpleToDnRealm.getRealmIdentity(new NamePrincipal("userToChange"));
        assertNotNull(identity);

        assertEquals(SupportLevel.POSSIBLY_SUPPORTED, simpleToDnRealm.getCredentialAcquireSupport(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null));
        assertEquals(SupportLevel.SUPPORTED, identity.getCredentialAcquireSupport(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null));

        identity.setCredentials(Collections.singleton(new PasswordCredential(password)));

        ModifiableRealmIdentity newIdentity = (ModifiableRealmIdentity) simpleToDnRealm.getRealmIdentity(new NamePrincipal("userToChange"));
        assertNotNull(newIdentity);

        verifyPasswordSupport(newIdentity, ClearPassword.ALGORITHM_CLEAR, SupportLevel.SUPPORTED);

        ClearPassword password2 = newIdentity.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR).getPassword(ClearPassword.class);
        assertNotNull(password2);
        Assert.assertEquals("createdPassword", new String(password2.getPassword()));
    }

    private void performSimpleNameTest(String simpleName, String algorithm, char[] password) throws NoSuchAlgorithmException, InvalidKeyException, RealmUnavailableException {
        performSimpleNameTest(simpleName, algorithm, password, StandardCharsets.UTF_8, simpleToDnRealm);
    }

    private void performSimpleNameTest(String simpleName, String algorithm, char[] password, Charset hashCharset, SecurityRealm realm) throws NoSuchAlgorithmException, InvalidKeyException, RealmUnavailableException {
        RealmIdentity realmIdentity = realm.getRealmIdentity(new NamePrincipal(simpleName));
        SupportLevel support = realm.getCredentialAcquireSupport(PasswordCredential.class, algorithm, null);
        assertEquals("Pre identity", SupportLevel.POSSIBLY_SUPPORTED, support);

        verifyPasswordSupport(realmIdentity, algorithm, SupportLevel.SUPPORTED);
        verifyPassword(realmIdentity, algorithm, password, hashCharset);
    }

    private void verifyPasswordSupport(RealmIdentity identity, final String algorithm, SupportLevel requiredSupport) throws RealmUnavailableException {
        SupportLevel credentialSupport = identity.getCredentialAcquireSupport(PasswordCredential.class, algorithm, null);
        assertEquals("Identity level support", requiredSupport, credentialSupport);
    }

    private void verifyPassword(RealmIdentity identity, String algorithm, char[] password, Charset hashCharset) throws NoSuchAlgorithmException, InvalidKeyException, RealmUnavailableException {
        Password loadedPassword = identity.getCredential(PasswordCredential.class).getPassword();

        PasswordFactory factory = PasswordFactory.getInstance(algorithm, WildFlyElytronPasswordProvider.getInstance());
        final Password translated = factory.translate(loadedPassword);
        assertTrue("Valid Password", factory.verify(translated, password, hashCharset));
        assertFalse("Invalid Password", factory.verify(translated, "LetMeIn".toCharArray()));
        Assert.assertTrue(identity.verifyEvidence(new PasswordGuessEvidence(password)));
    }
}
