/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.auth.server.ServerUtils.ELYTRON_PASSWORD_PROVIDERS;
import static org.wildfly.security.password.interfaces.BCryptPassword.BCRYPT_SALT_SIZE;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.SecretKey;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableRealmIdentityIterator;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.encryption.SecretKeyUtil;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.Encoding;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.OneTimePasswordSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
// has dependency on wildfly-elytron-realm, wildfly-elytron-auth-server, wildfly-elytron-credential
public class FileSystemSecurityRealmTest {

    private static final Provider provider = WildFlyElytronPasswordProvider.getInstance();

    public FileSystemSecurityRealmTest() throws GeneralSecurityException {
    }

    @BeforeClass
    public static void onBefore() throws Exception {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void onAfter() throws Exception {
        Security.removeProvider(provider.getName());
    }
    SecretKey key = SecretKeyUtil.generateSecretKey(128);

    @Test
    public void testCreateIdentityWithNoLevels() throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 0, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity identity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));

        assertFalse(identity.exists());

        identity.create();

        assertTrue(identity.exists());
    }


    @Test
    public void testCreateIdentityWithLevels() throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 3, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity identity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));

        identity.create();

        assertTrue(identity.exists());
        identity.dispose();
    }

    @Test
    public void testCreateIdentityWithLevelsEncryption() throws Exception {
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath(false))
                .setLevels(3)
                .setSecretKey(key)
                .build();
        ModifiableRealmIdentity identity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        assertFalse(identity.exists());
        identity.create();

        assertTrue(identity.exists());
        identity.dispose();
    }

    @Test
    public void testCreateAndLoadIdentity() throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 3, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        newIdentity.create();
        newIdentity.dispose();

        securityRealm = new FileSystemSecurityRealm(getRootPath(false), 3, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        assertTrue(existingIdentity.exists());
        existingIdentity.dispose();
    }

    @Test
    public void testCreateAndLoadIdentityEncryption() throws Exception {
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath())
                .setLevels(3)
                .setSecretKey(key)
                .build();
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        newIdentity.create();
        newIdentity.dispose();

        securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath(false))
                .setLevels(3)
                .setSecretKey(key)
                .build();
        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        assertTrue(existingIdentity.exists());
        existingIdentity.dispose();
    }

    @Test
    public void testShortUsername() throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 3, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("p"));
        newIdentity.create();

        newIdentity.dispose();

        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("p"));
        assertTrue(existingIdentity.exists());
        existingIdentity.dispose();
    }

    @Test
    public void testShortUsernameEncryption() throws Exception {
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder().setRoot(getRootPath()).setLevels(3).setSecretKey(key).build();
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("p"));
        newIdentity.create();

        newIdentity.dispose();

        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("p"));
        assertTrue(existingIdentity.exists());
        existingIdentity.dispose();
    }

    @Test
    public void testSpecialCharacters() throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 3, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("special*.\"/\\[]:;|=,用戶 "));
        newIdentity.create();
        newIdentity.dispose();

        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("special*.\"/\\[]:;|=,用戶 "));
        assertTrue(existingIdentity.exists());
        existingIdentity.dispose();
    }

    @Test
    public void testCaseSensitive() throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 3, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        newIdentity.create();
        assertTrue(newIdentity.exists());
        newIdentity.dispose();

        ModifiableRealmIdentity differentIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("PLAINUSER"));
        assertFalse(differentIdentity.exists());
        differentIdentity.dispose();
    }

    @Test
    public void testCaseSensitiveEncryption() throws Exception {
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath())
                .setLevels(3)
                .setSecretKey(key)
                .build();
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        newIdentity.create();
        assertTrue(newIdentity.exists());
        newIdentity.dispose();

        ModifiableRealmIdentity differentIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("PLAINUSER"));
        assertFalse(differentIdentity.exists());
        differentIdentity.dispose();
    }

    @Test
    public void testCreateAndLoadAndDeleteIdentity() throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 3, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        newIdentity.create();
        newIdentity.dispose();

        securityRealm = new FileSystemSecurityRealm(getRootPath(false), 3, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        assertTrue(existingIdentity.exists());
        existingIdentity.delete();
        assertFalse(existingIdentity.exists());
        existingIdentity.dispose();

        securityRealm = new FileSystemSecurityRealm(getRootPath(false), 3, ELYTRON_PASSWORD_PROVIDERS);
        existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        assertFalse(existingIdentity.exists());
        existingIdentity.dispose();
    }

    @Test
    public void testCreateAndLoadAndDeleteIdentityEncryption() throws Exception {
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath())
                .setLevels(3)
                .setSecretKey(key)
                .build();
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        newIdentity.create();
        newIdentity.dispose();

        securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath(false))
                .setLevels(3)
                .setSecretKey(key)
                .build();
        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        assertTrue(existingIdentity.exists());
        existingIdentity.delete();
        assertFalse(existingIdentity.exists());
        existingIdentity.dispose();

        securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath(false))
                .setLevels(3)
                .setSecretKey(key)
                .build();
        existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        assertFalse(existingIdentity.exists());
        existingIdentity.dispose();
    }

    @Test
    public void testCreateIdentityWithAttributes() throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 1, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));

        newIdentity.create();

        MapAttributes newAttributes = new MapAttributes();

        newAttributes.addFirst("name", "plainUser");
        newAttributes.addAll("roles", Arrays.asList("Employee", "Manager", "Admin"));

        newIdentity.setAttributes(newAttributes);
        newIdentity.dispose();

        securityRealm = new FileSystemSecurityRealm(getRootPath(false), 1, ELYTRON_PASSWORD_PROVIDERS);

        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        AuthorizationIdentity authorizationIdentity = existingIdentity.getAuthorizationIdentity();
        Attributes existingAttributes = authorizationIdentity.getAttributes();
        existingIdentity.dispose();

        assertEquals(newAttributes.size(), existingAttributes.size());
        assertTrue(newAttributes.get("name").containsAll(existingAttributes.get("name")));
        assertTrue(newAttributes.get("roles").containsAll(existingAttributes.get("roles")));
    }

    @Test
    public void testCreateIdentityWithAttributesEncryption() throws Exception {
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath())
                .setLevels(1)
                .setSecretKey(key)
                .build();
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));

        newIdentity.create();

        MapAttributes newAttributes = new MapAttributes();

        newAttributes.addFirst("name", "plainUser");
        newAttributes.addAll("roles", Arrays.asList("Employee", "Manager", "Admin"));

        newIdentity.setAttributes(newAttributes);
        newIdentity.dispose();

        securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath(false))
                .setLevels(1)
                .setSecretKey(key)
                .build();

        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        AuthorizationIdentity authorizationIdentity = existingIdentity.getAuthorizationIdentity();
        Attributes existingAttributes = authorizationIdentity.getAttributes();
        existingIdentity.dispose();

        assertEquals(newAttributes.size(), existingAttributes.size());
        assertTrue(newAttributes.get("name").containsAll(existingAttributes.get("name")));
        assertTrue(newAttributes.get("roles").containsAll(existingAttributes.get("roles")));
    }

    @Test
    public void testCreateIdentityWithClearPassword() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, ELYTRON_PASSWORD_PROVIDERS);
        ClearPassword clearPassword = (ClearPassword) factory.generatePassword(new ClearPasswordSpec(actualPassword));

        assertCreateIdentityWithPassword(actualPassword, clearPassword);
    }

    @Test
    public void testCreateIdentityWithClearPasswordEncryption() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        ClearPassword clearPassword = (ClearPassword) factory.generatePassword(new ClearPasswordSpec(actualPassword));

        assertCreateIdentityWithPassword(actualPassword, clearPassword, key);
    }

    @Test
    public void testCreateIdentityWithBcryptCredential() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT, ELYTRON_PASSWORD_PROVIDERS);
        char[] actualPassword = "secretPassword".toCharArray();
        BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                new EncryptablePasswordSpec(actualPassword, new IteratedSaltedPasswordAlgorithmSpec(10, generateRandomSalt(BCRYPT_SALT_SIZE)))
        );

        assertCreateIdentityWithPassword(actualPassword, bCryptPassword);
    }

    @Test
    public void testCreateIdentityWithBcryptCredentialEncryption() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT);
        char[] actualPassword = "secretPassword".toCharArray();
        BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                new EncryptablePasswordSpec(actualPassword, new IteratedSaltedPasswordAlgorithmSpec(10, generateRandomSalt(BCRYPT_SALT_SIZE)))
        );

        assertCreateIdentityWithPassword(actualPassword, bCryptPassword, key);
    }

    @Test
    public void testCreateIdentityWithBcryptCredentialHexEncoded() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT, ELYTRON_PASSWORD_PROVIDERS);
        char[] actualPassword = "secretPassword".toCharArray();
        BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                new EncryptablePasswordSpec(actualPassword, new IteratedSaltedPasswordAlgorithmSpec(10, generateRandomSalt(BCRYPT_SALT_SIZE))));

        assertCreateIdentityWithPassword(actualPassword, bCryptPassword, Encoding.HEX, StandardCharsets.UTF_8);
    }

    @Test
    public void testCreateIdentityWithBcryptCredentialHexEncodedEncryption() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT);
        char[] actualPassword = "secretPassword".toCharArray();
        BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                new EncryptablePasswordSpec(actualPassword, new IteratedSaltedPasswordAlgorithmSpec(10, generateRandomSalt(BCRYPT_SALT_SIZE))));

        assertCreateIdentityWithPassword(actualPassword, bCryptPassword, Encoding.HEX, StandardCharsets.UTF_8, key);
    }

    @Test
    public void testCreateIdentityWithBcryptCredentialBase64AndCharset() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT, ELYTRON_PASSWORD_PROVIDERS);
        char[] actualPassword = "password密码".toCharArray();
        BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                new EncryptablePasswordSpec(actualPassword, new IteratedSaltedPasswordAlgorithmSpec(10, generateRandomSalt(BCRYPT_SALT_SIZE)),
                        Charset.forName("gb2312")));

        assertCreateIdentityWithPassword(actualPassword, bCryptPassword, Encoding.BASE64, Charset.forName("gb2312"));
    }

    @Test
    public void testCreateIdentityWithBcryptCredentialBase64AndCharsetEncryption() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT);
        char[] actualPassword = "password密码".toCharArray();
        BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                new EncryptablePasswordSpec(actualPassword, new IteratedSaltedPasswordAlgorithmSpec(10, generateRandomSalt(BCRYPT_SALT_SIZE)),
                        Charset.forName("gb2312")));

        assertCreateIdentityWithPassword(actualPassword, bCryptPassword, Encoding.BASE64, Charset.forName("gb2312"), key);
    }

    @Test
    public void testCreateIdentityWithBcryptCredentialHexEncodedAndCharset() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT, ELYTRON_PASSWORD_PROVIDERS);
        char[] actualPassword = "password密码".toCharArray();
        BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                new EncryptablePasswordSpec(actualPassword, new IteratedSaltedPasswordAlgorithmSpec(10, generateRandomSalt(BCRYPT_SALT_SIZE)), Charset.forName("gb2312"))
        );

        assertCreateIdentityWithPassword(actualPassword, bCryptPassword, Encoding.HEX, Charset.forName("gb2312"));
    }

    @Test
    public void testCreateIdentityWithScramCredential() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        byte[] salt = generateRandomSalt(BCRYPT_SALT_SIZE);
        PasswordFactory factory = PasswordFactory.getInstance(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256, ELYTRON_PASSWORD_PROVIDERS);
        EncryptablePasswordSpec encSpec = new EncryptablePasswordSpec(actualPassword, new IteratedSaltedPasswordAlgorithmSpec(4096, salt));
        ScramDigestPassword scramPassword = (ScramDigestPassword) factory.generatePassword(encSpec);

        assertCreateIdentityWithPassword(actualPassword, scramPassword);
    }

    @Test
    public void testCreateIdentityWithScramCredentialEncryption() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        byte[] salt = generateRandomSalt(BCRYPT_SALT_SIZE);
        PasswordFactory factory = PasswordFactory.getInstance(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256);
        EncryptablePasswordSpec encSpec = new EncryptablePasswordSpec(actualPassword, new IteratedSaltedPasswordAlgorithmSpec(4096, salt));
        ScramDigestPassword scramPassword = (ScramDigestPassword) factory.generatePassword(encSpec);

        assertCreateIdentityWithPassword(actualPassword, scramPassword, key);
    }

    @Test
    public void testCreateIdentityWithScramCredentialHexEncoded() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        byte[] salt = generateRandomSalt(BCRYPT_SALT_SIZE);
        PasswordFactory factory = PasswordFactory.getInstance(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256, ELYTRON_PASSWORD_PROVIDERS);
        EncryptablePasswordSpec encSpec = new EncryptablePasswordSpec(actualPassword, new IteratedSaltedPasswordAlgorithmSpec(4096, salt));
        ScramDigestPassword scramPassword = (ScramDigestPassword) factory.generatePassword(encSpec);

        assertCreateIdentityWithPassword(actualPassword, scramPassword, Encoding.HEX, StandardCharsets.UTF_8);
    }

    @Test
    public void testCreateIdentityWithScramCredentialHexEncodedAndCharset() throws Exception {
        char[] actualPassword = "passwordHyväää".toCharArray();
        byte[] salt = generateRandomSalt(BCRYPT_SALT_SIZE);
        PasswordFactory factory = PasswordFactory.getInstance(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256, ELYTRON_PASSWORD_PROVIDERS);
        EncryptablePasswordSpec encSpec = new EncryptablePasswordSpec(actualPassword, new IteratedSaltedPasswordAlgorithmSpec(4096, salt),
                Charset.forName("ISO-8859-1"));
        ScramDigestPassword scramPassword = (ScramDigestPassword) factory.generatePassword(encSpec);

        assertCreateIdentityWithPassword(actualPassword, scramPassword, Encoding.HEX, Charset.forName("ISO-8859-1"));
    }

    @Test
    public void testCreateIdentityWithDigest() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        PasswordFactory factory = PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_SHA_512, ELYTRON_PASSWORD_PROVIDERS);
        DigestPasswordAlgorithmSpec dpas = new DigestPasswordAlgorithmSpec("jsmith", "elytron");
        EncryptablePasswordSpec encryptableSpec = new EncryptablePasswordSpec(actualPassword, dpas);
        DigestPassword digestPassword = (DigestPassword) factory.generatePassword(encryptableSpec);

        assertCreateIdentityWithPassword(actualPassword, digestPassword);
    }

    @Test
    public void testCreateIdentityWithDigestEncryption() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        PasswordFactory factory = PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_SHA_512);
        DigestPasswordAlgorithmSpec dpas = new DigestPasswordAlgorithmSpec("jsmith", "elytron");
        EncryptablePasswordSpec encryptableSpec = new EncryptablePasswordSpec(actualPassword, dpas);
        DigestPassword digestPassword = (DigestPassword) factory.generatePassword(encryptableSpec);

        assertCreateIdentityWithPassword(actualPassword, digestPassword, key);
    }

    @Test
    public void testCreateIdentityWithDigestHexEncoded() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        PasswordFactory factory = PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_SHA_512, ELYTRON_PASSWORD_PROVIDERS);
        DigestPasswordAlgorithmSpec dpas = new DigestPasswordAlgorithmSpec("jsmith", "elytron");
        EncryptablePasswordSpec encryptableSpec = new EncryptablePasswordSpec(actualPassword, dpas);
        DigestPassword digestPassword = (DigestPassword) factory.generatePassword(encryptableSpec);

        assertCreateIdentityWithPassword(actualPassword, digestPassword, Encoding.HEX, StandardCharsets.UTF_8);
    }

    @Test
    public void testCreateIdentityWithDigestHexEncodedAndCharset() throws Exception {
        char[] actualPassword = "пароль".toCharArray();
        PasswordFactory factory = PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_SHA_512, ELYTRON_PASSWORD_PROVIDERS);
        DigestPasswordAlgorithmSpec dpas = new DigestPasswordAlgorithmSpec("jsmith", "elytron");
        EncryptablePasswordSpec encryptableSpec = new EncryptablePasswordSpec(actualPassword, dpas, Charset.forName("KOI8-R"));
        DigestPassword digestPassword = (DigestPassword) factory.generatePassword(encryptableSpec);

        assertCreateIdentityWithPassword(actualPassword, digestPassword, Encoding.HEX, Charset.forName("KOI8-R"));
    }

    @Test
    public void testCreateIdentityWithDigestHexEncodedAndCharsetEncryption() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        PasswordFactory factory = PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_SHA_512);
        DigestPasswordAlgorithmSpec dpas = new DigestPasswordAlgorithmSpec("jsmith", "elytron");
        EncryptablePasswordSpec encryptableSpec = new EncryptablePasswordSpec(actualPassword, dpas);
        DigestPassword digestPassword = (DigestPassword) factory.generatePassword(encryptableSpec);

        assertCreateIdentityWithPassword(actualPassword, digestPassword, Encoding.HEX, Charset.forName("KOI8-R"), key);
    }

    @Test
    public void testCreateIdentityWithSimpleDigest() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        EncryptablePasswordSpec eps = new EncryptablePasswordSpec(actualPassword, null);
        PasswordFactory passwordFactory = PasswordFactory.getInstance(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512, ELYTRON_PASSWORD_PROVIDERS);
        SimpleDigestPassword tsdp = (SimpleDigestPassword) passwordFactory.generatePassword(eps);

        assertCreateIdentityWithPassword(actualPassword, tsdp);
    }

    @Test
    public void testCreateIdentityWithSimpleDigestHexEncoded() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        EncryptablePasswordSpec eps = new EncryptablePasswordSpec(actualPassword, null);
        PasswordFactory passwordFactory = PasswordFactory.getInstance(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512, ELYTRON_PASSWORD_PROVIDERS);
        SimpleDigestPassword tsdp = (SimpleDigestPassword) passwordFactory.generatePassword(eps);

        assertCreateIdentityWithPassword(actualPassword, tsdp, Encoding.HEX, StandardCharsets.UTF_8);
    }

    @Test
    public void testCreateIdentityWithSimpleDigestHexEncodedAndCharset() throws Exception {
        char[] actualPassword = "password密码".toCharArray();
        EncryptablePasswordSpec eps = new EncryptablePasswordSpec(actualPassword, null, Charset.forName("gb2312"));
        PasswordFactory passwordFactory = PasswordFactory.getInstance(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512, ELYTRON_PASSWORD_PROVIDERS);
        SimpleDigestPassword tsdp = (SimpleDigestPassword) passwordFactory.generatePassword(eps);

        assertCreateIdentityWithPassword(actualPassword, tsdp, Encoding.HEX, Charset.forName("gb2312"));
    }

    @Test
    public void testCreateIdentityWithSimpleSaltedDigest() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        byte[] salt = generateRandomSalt(BCRYPT_SALT_SIZE);
        SaltedPasswordAlgorithmSpec spac = new SaltedPasswordAlgorithmSpec(salt);
        EncryptablePasswordSpec eps = new EncryptablePasswordSpec(actualPassword, spac);
        PasswordFactory passwordFactory = PasswordFactory.getInstance(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, ELYTRON_PASSWORD_PROVIDERS);
        SaltedSimpleDigestPassword tsdp = (SaltedSimpleDigestPassword) passwordFactory.generatePassword(eps);

        assertCreateIdentityWithPassword(actualPassword, tsdp);
    }

    @Test
    public void testCreateIdentityWithSimpleSaltedDigestHexEncoded() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        byte[] salt = generateRandomSalt(BCRYPT_SALT_SIZE);
        SaltedPasswordAlgorithmSpec spac = new SaltedPasswordAlgorithmSpec(salt);
        EncryptablePasswordSpec eps = new EncryptablePasswordSpec(actualPassword, spac);
        PasswordFactory passwordFactory = PasswordFactory.getInstance(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, ELYTRON_PASSWORD_PROVIDERS);
        SaltedSimpleDigestPassword tsdp = (SaltedSimpleDigestPassword) passwordFactory.generatePassword(eps);

        assertCreateIdentityWithPassword(actualPassword, tsdp, Encoding.HEX, StandardCharsets.UTF_8);
    }

    @Test
    public void testCreateIdentityWithSimpleSaltedDigestHexEncodedAndCharset() throws Exception {
        char[] actualPassword = "password密码".toCharArray();
        byte[] salt = generateRandomSalt(BCRYPT_SALT_SIZE);
        SaltedPasswordAlgorithmSpec spac = new SaltedPasswordAlgorithmSpec(salt);
        EncryptablePasswordSpec eps = new EncryptablePasswordSpec(actualPassword, spac, Charset.forName("gb2312"));
        PasswordFactory passwordFactory = PasswordFactory.getInstance(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, ELYTRON_PASSWORD_PROVIDERS);
        SaltedSimpleDigestPassword tsdp = (SaltedSimpleDigestPassword) passwordFactory.generatePassword(eps);

        assertCreateIdentityWithPassword(actualPassword, tsdp, Encoding.HEX, Charset.forName("gb2312"));
    }

    @Test
    public void testCreateIdentityWithSimpleSaltedDigestHexEncodedAndCharsetEncryption() throws Exception {
        char[] actualPassword = "password密码".toCharArray();
        byte[] salt = generateRandomSalt(BCRYPT_SALT_SIZE);
        SaltedPasswordAlgorithmSpec spac = new SaltedPasswordAlgorithmSpec(salt);
        EncryptablePasswordSpec eps = new EncryptablePasswordSpec(actualPassword, spac, Charset.forName("gb2312"));
        PasswordFactory passwordFactory = PasswordFactory.getInstance(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512);
        SaltedSimpleDigestPassword tsdp = (SaltedSimpleDigestPassword) passwordFactory.generatePassword(eps);

        assertCreateIdentityWithPassword(actualPassword, tsdp, Encoding.HEX, Charset.forName("gb2312"), key);
    }

    @Test
    public void testCreateIdentityWithEverything() throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 1, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));

        newIdentity.create();

        MapAttributes newAttributes = new MapAttributes();

        newAttributes.addFirst("firstName", "John");
        newAttributes.addFirst("lastName", "Smith");
        newAttributes.addAll("roles", Arrays.asList("Employee", "Manager", "Admin"));

        newIdentity.setAttributes(newAttributes);

        List<Credential> credentials = new ArrayList<>();

        PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT, ELYTRON_PASSWORD_PROVIDERS);
        BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                new EncryptablePasswordSpec("secretPassword".toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(10, generateRandomSalt(BCRYPT_SALT_SIZE)))
        );

        credentials.add(new PasswordCredential(bCryptPassword));

        byte[] hash = CodePointIterator.ofString("505d889f90085847").hexDecode().drain();
        String seed = "ke1234";
        PasswordFactory otpFactory = PasswordFactory.getInstance(OneTimePassword.ALGORITHM_OTP_SHA1, ELYTRON_PASSWORD_PROVIDERS);
        OneTimePassword otpPassword = (OneTimePassword) otpFactory.generatePassword(
                new OneTimePasswordSpec(hash, seed, 500)
        );
        credentials.add(new PasswordCredential(otpPassword));

        newIdentity.setCredentials(credentials);
        newIdentity.dispose();

        securityRealm = new FileSystemSecurityRealm(getRootPath(false), 1, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        assertTrue(existingIdentity.exists());
        assertTrue(existingIdentity.verifyEvidence(new PasswordGuessEvidence("secretPassword".toCharArray())));

        OneTimePassword otp = existingIdentity.getCredential(PasswordCredential.class, OneTimePassword.ALGORITHM_OTP_SHA1).getPassword(OneTimePassword.class);
        assertNotNull(otp);
        assertEquals(OneTimePassword.ALGORITHM_OTP_SHA1, otp.getAlgorithm());
        assertArrayEquals(hash, otp.getHash());
        assertEquals(seed, otp.getSeed());
        assertEquals(500, otp.getSequenceNumber());

        AuthorizationIdentity authorizationIdentity = existingIdentity.getAuthorizationIdentity();
        Attributes existingAttributes = authorizationIdentity.getAttributes();
        existingIdentity.dispose();

        assertEquals(newAttributes.size(), existingAttributes.size());
        assertTrue(newAttributes.get("firstName").containsAll(existingAttributes.get("firstName")));
        assertTrue(newAttributes.get("lastName").containsAll(existingAttributes.get("lastName")));
        assertTrue(newAttributes.get("roles").containsAll(existingAttributes.get("roles")));
    }

    @Test
    public void testCreateIdentityWithEverythingEncryption() throws Exception {
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath())
                .setLevels(1)
                .setSecretKey(key)
                .build();
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));

        newIdentity.create();

        MapAttributes newAttributes = new MapAttributes();

        newAttributes.addFirst("firstName", "John");
        newAttributes.addFirst("lastName", "Smith");
        newAttributes.addAll("roles", Arrays.asList("Employee", "Manager", "Admin"));

        newIdentity.setAttributes(newAttributes);

        List<Credential> credentials = new ArrayList<>();

        PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT);
        BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                new EncryptablePasswordSpec("secretPassword".toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(10, generateRandomSalt(BCRYPT_SALT_SIZE)))
        );

        credentials.add(new PasswordCredential(bCryptPassword));

        byte[] hash = CodePointIterator.ofString("505d889f90085847").hexDecode().drain();
        String seed = "ke1234";
        PasswordFactory otpFactory = PasswordFactory.getInstance(OneTimePassword.ALGORITHM_OTP_SHA1);
        OneTimePassword otpPassword = (OneTimePassword) otpFactory.generatePassword(
                new OneTimePasswordSpec(hash, seed, 500)
        );
        credentials.add(new PasswordCredential(otpPassword));

        newIdentity.setCredentials(credentials);
        newIdentity.dispose();

        securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath(false))
                .setLevels(1)
                .setSecretKey(key)
                .build();
        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        assertTrue(existingIdentity.exists());
        assertTrue(existingIdentity.verifyEvidence(new PasswordGuessEvidence("secretPassword".toCharArray())));

        OneTimePassword otp = existingIdentity.getCredential(PasswordCredential.class, OneTimePassword.ALGORITHM_OTP_SHA1).getPassword(OneTimePassword.class);
        assertNotNull(otp);
        assertEquals(OneTimePassword.ALGORITHM_OTP_SHA1, otp.getAlgorithm());
        assertArrayEquals(hash, otp.getHash());
        assertEquals(seed, otp.getSeed());
        assertEquals(500, otp.getSequenceNumber());

        AuthorizationIdentity authorizationIdentity = existingIdentity.getAuthorizationIdentity();
        Attributes existingAttributes = authorizationIdentity.getAttributes();
        existingIdentity.dispose();

        assertEquals(newAttributes.size(), existingAttributes.size());
        assertTrue(newAttributes.get("firstName").containsAll(existingAttributes.get("firstName")));
        assertTrue(newAttributes.get("lastName").containsAll(existingAttributes.get("lastName")));
        assertTrue(newAttributes.get("roles").containsAll(existingAttributes.get("roles")));
    }

    @Test
    public void testCredentialReplacing() throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 1, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity identity1 = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("testingUser"));
        identity1.create();

        List<Credential> credentials = new ArrayList<>();

        PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT, ELYTRON_PASSWORD_PROVIDERS);
        BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                new EncryptablePasswordSpec("secretPassword".toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(10, generateRandomSalt(BCRYPT_SALT_SIZE)))
        );
        credentials.add(new PasswordCredential(bCryptPassword));

        byte[] hash = CodePointIterator.ofString("505d889f90085847").hexDecode().drain();
        String seed = "ke1234";
        PasswordFactory otpFactory = PasswordFactory.getInstance(OneTimePassword.ALGORITHM_OTP_SHA1, ELYTRON_PASSWORD_PROVIDERS);
        OneTimePassword otpPassword = (OneTimePassword) otpFactory.generatePassword(
                new OneTimePasswordSpec(hash, seed, 500)
        );
        credentials.add(new PasswordCredential(otpPassword));

        identity1.setCredentials(credentials);
        identity1.dispose();

        // checking result
        securityRealm = new FileSystemSecurityRealm(getRootPath(false), 1, ELYTRON_PASSWORD_PROVIDERS);
        ModifiableRealmIdentity identity3 = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("testingUser"));

        assertTrue(identity3.exists());
        assertTrue(identity3.verifyEvidence(new PasswordGuessEvidence("secretPassword".toCharArray())));
        identity3.dispose();
    }

    @Test
    public void testCredentialReplacingEncryption() throws Exception {
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder()
            .setRoot(getRootPath())
            .setLevels(1)
            .setSecretKey(key)
            .build();
        ModifiableRealmIdentity identity1 = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("testingUser"));
        identity1.create();

        List<Credential> credentials = new ArrayList<>();

        PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT);
        BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                new EncryptablePasswordSpec("secretPassword".toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(10, generateRandomSalt(BCRYPT_SALT_SIZE)))
        );
        credentials.add(new PasswordCredential(bCryptPassword));

        byte[] hash = CodePointIterator.ofString("505d889f90085847").hexDecode().drain();
        String seed = "ke1234";
        PasswordFactory otpFactory = PasswordFactory.getInstance(OneTimePassword.ALGORITHM_OTP_SHA1);
        OneTimePassword otpPassword = (OneTimePassword) otpFactory.generatePassword(
                new OneTimePasswordSpec(hash, seed, 500)
        );
        credentials.add(new PasswordCredential(otpPassword));

        identity1.setCredentials(credentials);
        identity1.dispose();

        // checking result
        securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath(false))
                .setLevels(1)
                .setSecretKey(key)
                .build();
        ModifiableRealmIdentity identity3 = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("testingUser"));

        assertTrue(identity3.exists());
        assertTrue(identity3.verifyEvidence(new PasswordGuessEvidence("secretPassword".toCharArray())));
        identity3.dispose();
    }

    private FileSystemSecurityRealm createRealmWithTwoIdentities() throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 1);
        ModifiableRealmIdentity identity1 = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("firstUser"));
        identity1.create();
        identity1.dispose();
        ModifiableRealmIdentity identity2 = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("secondUser"));
        identity2.create();
        identity2.dispose();
        return securityRealm;
    }

    private FileSystemSecurityRealm createRealmWithTwoIdentities(SecretKey secretKey) throws Exception {
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath())
                .setLevels(1)
                .setSecretKey(secretKey)
                .build();
        ModifiableRealmIdentity identity1 = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("firstUser"));
        identity1.create();
        identity1.dispose();
        ModifiableRealmIdentity identity2 = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("secondUser"));
        identity2.create();
        identity2.dispose();
        return securityRealm;
    }

    @Test
    public void testIterating() throws Exception {
        FileSystemSecurityRealm securityRealm = createRealmWithTwoIdentities();
        Iterator<ModifiableRealmIdentity> iterator = securityRealm.getRealmIdentityIterator();

        int count = 0;
        while(iterator.hasNext()){
            Assert.assertTrue(iterator.next().exists());
            count++;
        }

        Assert.assertEquals(2, count);
        getRootPath(); // will fail on windows if iterator not closed correctly
    }

    @Test
    public void testIteratingEncryption() throws Exception {
        FileSystemSecurityRealm securityRealm = createRealmWithTwoIdentities(key);
        Iterator<ModifiableRealmIdentity> iterator = securityRealm.getRealmIdentityIterator();

        int count = 0;
        while(iterator.hasNext()){
            Assert.assertTrue(iterator.next().exists());
            count++;
        }

        Assert.assertEquals(2, count);
        getRootPath(); // will fail on windows if iterator not closed correctly
    }

    @Test
    public void testIteratingNeedlessClose() throws Exception {
        FileSystemSecurityRealm securityRealm = createRealmWithTwoIdentities();
        ModifiableRealmIdentityIterator iterator = securityRealm.getRealmIdentityIterator();

        int count = 0;
        while(iterator.hasNext()){
            Assert.assertTrue(iterator.next().exists());
            count++;
        }
        Assert.assertEquals(2, count);
        iterator.close(); // needless, already closed
        getRootPath(); // will fail on windows if iterator not closed correctly
    }

    @Test
    public void testPartialIterating() throws Exception {
        FileSystemSecurityRealm securityRealm = createRealmWithTwoIdentities();
        ModifiableRealmIdentityIterator iterator = securityRealm.getRealmIdentityIterator();

        Assert.assertTrue(iterator.hasNext());
        Assert.assertTrue(iterator.next().exists());
        iterator.close();
        getRootPath(); // will fail on windows if iterator not closed correctly
    }

    @Test
    public void testPartialIteratingTryWithResource() throws Exception {
        FileSystemSecurityRealm securityRealm = createRealmWithTwoIdentities();
        try(ModifiableRealmIdentityIterator iterator = securityRealm.getRealmIdentityIterator()) {
            Assert.assertTrue(iterator.hasNext());
            Assert.assertTrue(iterator.next().exists());
        } // try should ensure iterator closing
        getRootPath(); // will fail on windows if iterator not closed correctly
    }

    @Test(expected = RealmUnavailableException.class)
    public void testMismatchSecretKey() throws Exception {
        char[] actualPassword = "secretPassword".toCharArray();
        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        ClearPassword clearPassword = (ClearPassword) factory.generatePassword(new ClearPasswordSpec(actualPassword));
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath())
                .setLevels(2)
                .setSecretKey(key)
                .build();
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        newIdentity.create();
        newIdentity.setCredentials(Collections.singleton(new PasswordCredential(clearPassword)));
        securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath(false))
                .setLevels(2)
                .setSecretKey(SecretKeyUtil.generateSecretKey(192))
                .build();
        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        existingIdentity.verifyEvidence(new PasswordGuessEvidence(actualPassword));
        existingIdentity.dispose();
    }

    @Test
    public void encodedIfNotEncrypted() throws Exception {
        File file = new File(getRootPath().toString() + "/plainuser-OBWGC2LOKVZWK4Q.xml");
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath())
                .setLevels(0)
                .setEncoded(true)
                .build();
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        newIdentity.create();
        assertTrue(file.isFile());
        newIdentity.dispose();
        securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath())
                .setLevels(0)
                .setEncoded(true)
                .setSecretKey(key)
                .build();
        newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        newIdentity.create();
        assertFalse(file.isFile());

    }

    private void assertCreateIdentityWithPassword(char[] actualPassword, Password credential) throws Exception {
        assertCreateIdentityWithPassword(actualPassword, credential, Encoding.BASE64, StandardCharsets.UTF_8);
    }
    private void assertCreateIdentityWithPassword(char[] actualPassword, Password credential, SecretKey secretKey) throws Exception {
        assertCreateIdentityWithPassword(actualPassword, credential, Encoding.BASE64, StandardCharsets.UTF_8, secretKey);
    }

    private void assertCreateIdentityWithPassword(char[] actualPassword, Password credential, Encoding hashEncoding, Charset hashCharset) throws Exception {
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), NameRewriter.IDENTITY_REWRITER, 1, true, hashEncoding, hashCharset, ELYTRON_PASSWORD_PROVIDERS, null);
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        newIdentity.create();
        newIdentity.setCredentials(Collections.singleton(new PasswordCredential(credential)));
        newIdentity.dispose();

        securityRealm = new FileSystemSecurityRealm(getRootPath(false), NameRewriter.IDENTITY_REWRITER, 1, true, hashEncoding, hashCharset, ELYTRON_PASSWORD_PROVIDERS, null);
        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        assertTrue(existingIdentity.exists());
        assertTrue(existingIdentity.verifyEvidence(new PasswordGuessEvidence(actualPassword)));
        existingIdentity.dispose();
    }

    private void assertCreateIdentityWithPassword(char[] actualPassword, Password credential, Encoding hashEncoding, Charset hashCharset, SecretKey secretKey) throws Exception {
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath())
                .setLevels(1)
                .setHashEncoding(hashEncoding)
                .setHashCharset(hashCharset)
                .setSecretKey(secretKey)
                .build();
        ModifiableRealmIdentity newIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        newIdentity.create();
        newIdentity.setCredentials(Collections.singleton(new PasswordCredential(credential)));
        newIdentity.dispose();

        securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(getRootPath(false))
                .setLevels(1)
                .setHashEncoding(hashEncoding)
                .setHashCharset(hashCharset)
                .setSecretKey(secretKey)
                .build();
        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("plainUser"));
        assertTrue(existingIdentity.exists());
        assertTrue(existingIdentity.verifyEvidence(new PasswordGuessEvidence(actualPassword)));
        existingIdentity.dispose();
    }

    private static byte[] generateRandomSalt(int saltSize) {
        byte[] randomSalt = new byte[saltSize];
        ThreadLocalRandom.current().nextBytes(randomSalt);
        return randomSalt;
    }

    private Path getRootPath(boolean deleteIfExists) throws Exception {
        Path rootPath = Paths.get(getClass().getResource(File.separator).toURI())
                .resolve("filesystem-realm");

        if (rootPath.toFile().exists() && !deleteIfExists) {
            return rootPath;
        }

        return Files.walkFileTree(Files.createDirectories(rootPath), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private Path getRootPath() throws Exception {
        return getRootPath(true);
    }

}
