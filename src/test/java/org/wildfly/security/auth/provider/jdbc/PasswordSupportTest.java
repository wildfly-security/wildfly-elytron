/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.auth.provider.jdbc;

import org.junit.ClassRule;
import org.junit.Test;
import org.wildfly.security.auth.provider.jdbc.mapper.PasswordKeyMapper;
import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.util.ModularCrypt;
import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedSaltedHashPasswordSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.util.PasswordUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.password.interfaces.BCryptPassword.BCRYPT_SALT_SIZE;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PasswordSupportTest {

    @ClassRule
    public static final DataSourceRule dataSourceRule = new DataSourceRule();

    @Test
    public void testVerifyAndObtainClearPasswordCredential() throws Exception {
        String userName = "john";
        String userPassword = "abcd1234";

        createClearPasswordTable(userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password FROM user_clear_password WHERE name = ?")
                    .withMapper(new PasswordKeyMapper("cred1", ClearPassword.ALGORITHM_CLEAR, 1))
                    .from(dataSourceRule.getDataSource())
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport("cred1"));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport("cred1"));

        PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        ClearPassword password = (ClearPassword) passwordFactory.generatePassword(new ClearPasswordSpec(userPassword.toCharArray()));

        assertTrue(realmIdentity.verifyEvidence("cred1", new PasswordGuessEvidence(userPassword.toCharArray())));

        PasswordGuessEvidence invalidPassword = new PasswordGuessEvidence("badpasswd".toCharArray());

        assertFalse(realmIdentity.verifyEvidence("cred1", invalidPassword));
        assertFalse(realmIdentity.verifyEvidence("cred2", invalidPassword));

        ClearPassword storedPassword = (ClearPassword) realmIdentity.getCredential("cred1", PasswordCredential.class).getPassword();

        assertNotNull(storedPassword);
        assertArrayEquals(password.getPassword(), storedPassword.getPassword());
    }

    @Test
    public void testVerifyAndObtainBCryptPasswordCredentialUsingModularCrypt() throws Exception {
        String userName = "john";
        String userPassword = "bcrypt_abcd1234";

        String cryptString = createBcryptPasswordTable(userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password FROM user_bcrypt_password where name = ?")
                .withMapper(
                        new PasswordKeyMapper("cred2", BCryptPassword.ALGORITHM_BCRYPT, 1)
                )
                .from(dataSourceRule.getDataSource())
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport("cred2"));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport("cred2"));
        assertTrue(realmIdentity.verifyEvidence("cred2", new PasswordGuessEvidence(userPassword.toCharArray())));
        assertFalse(realmIdentity.verifyEvidence("cred2", new PasswordGuessEvidence("invalid".toCharArray())));

        BCryptPassword storedPassword = (BCryptPassword) realmIdentity.getCredential("cred2", PasswordCredential.class).getPassword();

        assertNotNull(storedPassword);

        // use the new password to obtain a spec and then check if the spec yields the same crypt string.
        assertEquals(cryptString, ModularCrypt.encodeAsString(storedPassword));
    }

    @Test
    public void testVerifyAndObtainBCryptPasswordCredential() throws Exception {
        String userName = "john";
        String userPassword = "bcrypt_abcd1234";
        byte[] salt = PasswordUtil.generateRandomSalt(BCRYPT_SALT_SIZE);
        int iterationCount = 10;

        createBcryptPasswordTable(userName, userPassword, salt, iterationCount);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password, salt, iterationCount FROM user_bcrypt_password where name = ?")
                .withMapper(
                        new PasswordKeyMapper("cred3", BCryptPassword.ALGORITHM_BCRYPT, 1, 2, 3)
                )
                .from(dataSourceRule.getDataSource())
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport("cred3"));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport("cred3"));
        assertTrue(realmIdentity.verifyEvidence("cred3", new PasswordGuessEvidence(userPassword.toCharArray())));
        assertFalse(realmIdentity.verifyEvidence("cred3", new PasswordGuessEvidence("invalid".toCharArray())));

        BCryptPassword storedPassword = (BCryptPassword) realmIdentity.getCredential("cred3", PasswordCredential.class).getPassword();

        assertNotNull(storedPassword);
    }

    @Test
    public void testVerifyAndObtainSaltedDigestPasswordCredential() throws Exception {
        assertVerifyAndObtainSaltedDigestPasswordCredential(SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512);
        assertVerifyAndObtainSaltedDigestPasswordCredential(SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1);
        assertVerifyAndObtainSaltedDigestPasswordCredential(SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384);
        assertVerifyAndObtainSaltedDigestPasswordCredential(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512);
        assertVerifyAndObtainSaltedDigestPasswordCredential(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1);
        assertVerifyAndObtainSaltedDigestPasswordCredential(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384);
    }

    public void assertVerifyAndObtainSaltedDigestPasswordCredential(String algorithm) throws Exception {
        String userName = "john";
        String userPassword = "salted_digest_abcd1234";

        SaltedSimpleDigestPassword password = createSaltedDigestPasswordTable(algorithm, userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT digest, salt FROM user_salted_digest_password where name = ?")
                .withMapper(
                        new PasswordKeyMapper("cred4", algorithm, 1, 2)
                )
                .from(dataSourceRule.getDataSource())
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport("cred4"));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport("cred4"));
        assertTrue(realmIdentity.verifyEvidence("cred4", new PasswordGuessEvidence(userPassword.toCharArray())));

        SaltedSimpleDigestPassword storedPassword = (SaltedSimpleDigestPassword) realmIdentity.getCredential("cred4", PasswordCredential.class).getPassword();

        assertNotNull(storedPassword);
        assertArrayEquals(password.getDigest(), storedPassword.getDigest());
        assertArrayEquals(password.getSalt(), storedPassword.getSalt());
    }

    @Test
    public void testVerifySimpleDigestPasswordCredential() throws Exception {
        assertVerifyAndObtainSimpleDigestPasswordSHA512Credential(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512);
        assertVerifyAndObtainSimpleDigestPasswordSHA512Credential(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5);
        assertVerifyAndObtainSimpleDigestPasswordSHA512Credential(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD2);
    }

    public void assertVerifyAndObtainSimpleDigestPasswordSHA512Credential(String algorithm) throws Exception {
        String userName = "john";
        String userPassword = "simple_digest_abcd1234";

        SimpleDigestPassword password = createSimpleDigestPasswordTable(algorithm, userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT digest FROM user_simple_digest_password where name = ?")
                .withMapper(
                        new PasswordKeyMapper("cred5", algorithm, 1)
                )
                .from(dataSourceRule.getDataSource())
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport("cred5"));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport("cred5"));
        assertTrue(realmIdentity.verifyEvidence("cred5", new PasswordGuessEvidence(userPassword.toCharArray())));

        SimpleDigestPassword storedPassword = (SimpleDigestPassword) realmIdentity.getCredential("cred5", PasswordCredential.class).getPassword();

        assertNotNull(storedPassword);
        assertArrayEquals(password.getDigest(), storedPassword.getDigest());
    }

    @Test
    public void testVerifyAndObtainScramDigestPasswordCredential() throws Exception {
        String userName = "john";
        String userPassword = "scram_digest_abcd1234";

        IteratedSaltedHashPasswordSpec passwordSpec = createScramDigestPasswordTable(userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT digest, salt, iterationCount FROM user_scram_digest_password where name = ?")
                .withMapper(
                        new PasswordKeyMapper("cred6", ScramDigestPassword.ALGORITHM_SCRAM_SHA_256, 1, 2, 3)
                )
                .from(dataSourceRule.getDataSource())
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport("cred6"));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport("cred6"));
        assertTrue(realmIdentity.verifyEvidence("cred6", new PasswordGuessEvidence(userPassword.toCharArray())));

        ScramDigestPassword storedPassword = (ScramDigestPassword) realmIdentity.getCredential("cred6", PasswordCredential.class).getPassword();

        assertNotNull(storedPassword);
        assertArrayEquals(passwordSpec.getHash(), storedPassword.getDigest());
        assertArrayEquals(passwordSpec.getSalt(), storedPassword.getSalt());
        assertEquals(passwordSpec.getIterationCount(), storedPassword.getIterationCount());
    }

    private SaltedSimpleDigestPassword createSaltedDigestPasswordTable(String algorithm, String userName, String userPassword) throws Exception {
        try (
            Connection connection = dataSourceRule.getDataSource().getConnection();
            Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DROP TABLE IF EXISTS user_salted_digest_password");
            statement.executeUpdate("CREATE TABLE user_salted_digest_password ( id INTEGER IDENTITY, name VARCHAR(100), digest OTHER, salt OTHER)");
        }

        try (
            Connection connection = dataSourceRule.getDataSource().getConnection();
            PreparedStatement  preparedStatement = connection.prepareStatement("INSERT INTO user_salted_digest_password (name, digest, salt) VALUES (?, ?, ?)");
        ) {
            byte[] salt = PasswordUtil.generateRandomSalt(BCRYPT_SALT_SIZE);
            SaltedPasswordAlgorithmSpec spac = new SaltedPasswordAlgorithmSpec(salt);
            EncryptablePasswordSpec eps = new EncryptablePasswordSpec(userPassword.toCharArray(), spac);
            PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
            SaltedSimpleDigestPassword tsdp = (SaltedSimpleDigestPassword) passwordFactory.generatePassword(eps);

            preparedStatement.setString(1, userName);
            preparedStatement.setBytes(2, tsdp.getDigest());
            preparedStatement.setBytes(3, tsdp.getSalt());
            preparedStatement.execute();

            return tsdp;
        }
    }

    private SimpleDigestPassword createSimpleDigestPasswordTable(String algorithm, String userName, String userPassword) throws Exception {
        try (
            Connection connection = dataSourceRule.getDataSource().getConnection();
            Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DROP TABLE IF EXISTS user_simple_digest_password");
            statement.executeUpdate("CREATE TABLE user_simple_digest_password ( id INTEGER IDENTITY, name VARCHAR(100), digest OTHER)");
        }

        try (
            Connection connection = dataSourceRule.getDataSource().getConnection();
            PreparedStatement  preparedStatement = connection.prepareStatement("INSERT INTO user_simple_digest_password (name, digest) VALUES (?, ?)");
        ) {
            EncryptablePasswordSpec eps = new EncryptablePasswordSpec(userPassword.toCharArray(), null);
            PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
            SimpleDigestPassword tsdp = (SimpleDigestPassword) passwordFactory.generatePassword(eps);

            preparedStatement.setString(1, userName);
            preparedStatement.setBytes(2, tsdp.getDigest());
            preparedStatement.execute();

            return tsdp;
        }
    }

    private IteratedSaltedHashPasswordSpec createScramDigestPasswordTable(String userName, String userPassword) throws Exception {
        try (
            Connection connection = dataSourceRule.getDataSource().getConnection();
            Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DROP TABLE IF EXISTS user_scram_digest_password");
            statement.executeUpdate("CREATE TABLE user_scram_digest_password ( id INTEGER IDENTITY, name VARCHAR(100), digest OTHER, salt OTHER, iterationCount INTEGER)");
        }

        try (
            Connection connection = dataSourceRule.getDataSource().getConnection();
            PreparedStatement  preparedStatement = connection.prepareStatement("INSERT INTO user_scram_digest_password (name, digest, salt, iterationCount) VALUES (?, ?, ?, ?)");
        ) {
            byte[] salt = PasswordUtil.generateRandomSalt(BCRYPT_SALT_SIZE);
            PasswordFactory factory = PasswordFactory.getInstance(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256);
            IteratedSaltedPasswordAlgorithmSpec algoSpec = new IteratedSaltedPasswordAlgorithmSpec(4096, salt);
            EncryptablePasswordSpec encSpec = new EncryptablePasswordSpec(userPassword.toCharArray(), algoSpec);
            ScramDigestPassword scramPassword = (ScramDigestPassword) factory.generatePassword(encSpec);
            IteratedSaltedHashPasswordSpec keySpec = factory.getKeySpec(scramPassword, IteratedSaltedHashPasswordSpec.class);

            preparedStatement.setString(1, userName);
            preparedStatement.setBytes(2, keySpec.getHash());
            preparedStatement.setBytes(3, keySpec.getSalt());
            preparedStatement.setInt(4, keySpec.getIterationCount());
            preparedStatement.execute();

            return keySpec;
        }
    }

    private String createBcryptPasswordTable(String userName, String userPassword) throws Exception {
        try (
            Connection connection = dataSourceRule.getDataSource().getConnection();
            Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DROP TABLE IF EXISTS user_bcrypt_password");
            statement.executeUpdate("CREATE TABLE user_bcrypt_password ( id INTEGER IDENTITY, name VARCHAR(100), password VARCHAR(100))");
        }

        try (
            Connection connection = dataSourceRule.getDataSource().getConnection();
            PreparedStatement  preparedStatement = connection.prepareStatement("INSERT INTO user_bcrypt_password (name, password) VALUES (?, ?)");
        ) {
            byte[] salt = PasswordUtil.generateRandomSalt(BCRYPT_SALT_SIZE);
            PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT);
            BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                    new EncryptablePasswordSpec(userPassword.toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(10, salt))
            );
            String cryptString = ModularCrypt.encodeAsString(bCryptPassword);

            preparedStatement.setString(1, userName);
            preparedStatement.setString(2, cryptString);
            preparedStatement.execute();

            return cryptString;
        }
    }

    private void createBcryptPasswordTable(String userName, String userPassword, byte[] salt, int iterationCount) throws Exception {
        try (
                Connection connection = dataSourceRule.getDataSource().getConnection();
                Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DROP TABLE IF EXISTS user_bcrypt_password");
            statement.executeUpdate("CREATE TABLE user_bcrypt_password ( id INTEGER IDENTITY, name VARCHAR(100), password OTHER, salt OTHER, iterationCount INTEGER)");
        }

        try (
                Connection connection = dataSourceRule.getDataSource().getConnection();
                PreparedStatement  preparedStatement = connection.prepareStatement("INSERT INTO user_bcrypt_password (name, password, salt, iterationCount) VALUES (?, ?, ?, ?)");
        ) {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT);
            BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                    new EncryptablePasswordSpec(userPassword.toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(iterationCount, salt))
            );

            preparedStatement.setString(1, userName);
            preparedStatement.setBytes(2, bCryptPassword.getHash());
            preparedStatement.setBytes(3, bCryptPassword.getSalt());
            preparedStatement.setInt(4, bCryptPassword.getIterationCount());
            preparedStatement.execute();
        }
    }

    private void createClearPasswordTable(String userName, String password) throws Exception {
        createClearPasswordTable();
        insertUserWithClearPassword(userName, password);
    }

    private void insertUserWithClearPassword(String userName, String password) throws SQLException {
        try (
            Connection connection = dataSourceRule.getDataSource().getConnection();
            Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("INSERT INTO user_clear_password (name, password) VALUES ('" + userName + "','" + password + "')");
        }
    }

    private void createClearPasswordTable() throws Exception {
        try (
            Connection connection = dataSourceRule.getDataSource().getConnection();
            Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DROP TABLE IF EXISTS user_clear_password");
            statement.executeUpdate("CREATE TABLE user_clear_password ( id INTEGER IDENTITY, name VARCHAR(100), password VARCHAR(50))");
        }
    }
}