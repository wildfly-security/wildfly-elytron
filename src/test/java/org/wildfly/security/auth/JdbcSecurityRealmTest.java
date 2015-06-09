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
package org.wildfly.security.auth;

import org.hsqldb.jdbc.JDBCDataSource;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.provider.jdbc.JdbcSecurityRealm;
import org.wildfly.security.auth.provider.jdbc.mapper.PasswordKeyMapper;
import org.wildfly.security.auth.provider.jdbc.mapper.RSAPrivateKeyMapper;
import org.wildfly.security.auth.spi.CredentialSupport;
import org.wildfly.security.auth.spi.RealmIdentity;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.PasswordUtil;
import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.spec.BCryptPasswordSpec;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.ScramDigestPasswordSpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.password.interfaces.BCryptPassword.BCRYPT_SALT_SIZE;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JdbcSecurityRealmTest {

    private static final Provider elytronProvider = new WildFlyElytronProvider();

    @BeforeClass
    public static void registerProvider() {
        Security.addProvider(elytronProvider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(elytronProvider.getName());
    }

    private JDBCDataSource dataSource;

    @Before
    public void onBefore() throws Exception {
        this.dataSource = new JDBCDataSource();
        this.dataSource.setDatabase("mem:elytron-jdbc-realm-test");
        this.dataSource.setUser("sa");
    }

    @Test
    public void testVerifyClearPasswordCredential() throws Exception {
        String userName = "john";
        String userPassword = "abcd1234";

        createClearPasswordTable(userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .authenticationQuery("SELECT password FROM user_clear_password WHERE name = ?")
                    .withMapper(new PasswordKeyMapper(ClearPassword.ALGORITHM_CLEAR, 1))
                    .from(this.dataSource)
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport(ClearPassword.class));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(ClearPassword.class));

        PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        Password password = passwordFactory.generatePassword(new ClearPasswordSpec(userPassword.toCharArray()));

        assertTrue(realmIdentity.verifyCredential(password));
        assertTrue(realmIdentity.verifyCredential(userPassword));
        assertTrue(realmIdentity.verifyCredential(userPassword.toCharArray()));

        Password invalidPassword = passwordFactory.generatePassword(new ClearPasswordSpec("badpasswd".toCharArray()));

        assertFalse(realmIdentity.verifyCredential(invalidPassword));
    }

    @Test
    public void testObtainClearPasswordCredential() throws Exception {
        String userName = "john";
        String userPassword = "abcd1234";

        createClearPasswordTable(userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .authenticationQuery("SELECT password FROM user_clear_password WHERE name = ?")
                .withMapper(new PasswordKeyMapper(ClearPassword.ALGORITHM_CLEAR, 1))
                .from(this.dataSource)
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport(ClearPassword.class));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(ClearPassword.class));

        ClearPassword credential = realmIdentity.getCredential(ClearPassword.class);

        assertNotNull(credential);
    }

    @Test
    public void testVerifyBCryptPasswordCredential() throws Exception {
        String userName = "john";
        String userPassword = "bcrypt_abcd1234";

        createBcryptPasswordTable(userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .authenticationQuery("SELECT password FROM user_bcrypt_password where name = ?")
                .withMapper(
                        new PasswordKeyMapper(BCryptPassword.ALGORITHM_BCRYPT, 1)
                )
                .from(this.dataSource)
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport(BCryptPassword.class));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(BCryptPassword.class));

        assertTrue(realmIdentity.verifyCredential(userPassword));
        assertFalse(realmIdentity.verifyCredential("invalid"));
    }

    @Test
    public void testObtainBCryptPasswordCredential() throws Exception {
        String userName = "john";
        String userPassword = "bcrypt_abcd1234";

        createBcryptPasswordTable(userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .authenticationQuery("SELECT password FROM user_bcrypt_password where name = ?")
                .withMapper(
                        new PasswordKeyMapper(BCryptPassword.ALGORITHM_BCRYPT, 1)
                )
                .from(this.dataSource)
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport(BCryptPassword.class));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(BCryptPassword.class));

        BCryptPassword credential = realmIdentity.getCredential(BCryptPassword.class);

        assertNotNull(credential);
    }

    @Test
    public void testVerifySaltedDigestPasswordCredential() throws Exception {
        String userName = "john";
        String userPassword = "salted_digest_abcd1234";

        createSaltedDigestPasswordTable(userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .authenticationQuery("SELECT digest, salt FROM user_salted_digest_password where name = ?")
                .withMapper(
                        new PasswordKeyMapper(SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512, 1, 2)
                )
                .from(this.dataSource)
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport(SaltedSimpleDigestPassword.class));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(SaltedSimpleDigestPassword.class));

        assertTrue(realmIdentity.verifyCredential(userPassword));
    }

    @Test
    public void testObtainSaltedDigestPasswordCredential() throws Exception {
        String userName = "john";
        String userPassword = "salted_digest_abcd1234";

        createSaltedDigestPasswordTable(userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .authenticationQuery("SELECT digest, salt FROM user_salted_digest_password where name = ?")
                .withMapper(
                        new PasswordKeyMapper(SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512, 1, 2)
                )
                .from(this.dataSource)
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport(SaltedSimpleDigestPassword.class));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(SaltedSimpleDigestPassword.class));

        SaltedSimpleDigestPassword credential = realmIdentity.getCredential(SaltedSimpleDigestPassword.class);

        assertNotNull(credential);
    }

    @Test
    public void testVerifyScramDigestPasswordCredential() throws Exception {
        String userName = "john";
        String userPassword = "scram_digest_abcd1234";

        createScramDigestPasswordTable(userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .authenticationQuery("SELECT digest, salt, iterationCount FROM user_scram_digest_password where name = ?")
                .withMapper(
                        new PasswordKeyMapper(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256, 1, 2, 3)
                )
                .from(this.dataSource)
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport(ScramDigestPassword.class));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(ScramDigestPassword.class));

        assertTrue(realmIdentity.verifyCredential(userPassword));
    }

    @Test
    public void testObtainScramDigestPasswordCredential() throws Exception {
        String userName = "john";
        String userPassword = "scram_digest_abcd1234";

        createScramDigestPasswordTable(userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .authenticationQuery("SELECT digest, salt, iterationCount FROM user_scram_digest_password where name = ?")
                .withMapper(
                        new PasswordKeyMapper(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256, 1, 2, 3)
                )
                .from(this.dataSource)
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport(ScramDigestPassword.class));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(ScramDigestPassword.class));

        ScramDigestPassword credential = realmIdentity.getCredential(ScramDigestPassword.class);

        assertNotNull(credential);
    }

    @Test
    public void testObtainPrivateKeyCredential() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = rsa.generateKeyPair();
        String userName = "john";
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        createRSAKeysTable(userName, privateKey, publicKey);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .authenticationQuery("SELECT privateKey FROM user_rsa_keys where name = ?")
                .withMapper(new RSAPrivateKeyMapper(1))
                .from(this.dataSource)
                .build();

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        PrivateKey identityPrivateKey = realmIdentity.getCredential(PrivateKey.class);

        assertNotNull(identityPrivateKey);
        assertEquals(privateKey, identityPrivateKey);
    }

    @Test
    public void testObtainMultipleCredentialsFromQueryJoin() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = rsa.generateKeyPair();
        String userName = "john";
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        createRSAKeysTable(userName, privateKey, publicKey);

        String userPassword = "john_abcd1234";

        createClearPasswordTable(userName, userPassword);

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .authenticationQuery("SELECT pk.privateKey, cp.password FROM user_rsa_keys pk INNER JOIN user_clear_password cp on cp.name = pk.name WHERE pk.name = ?")
                .withMapper(new RSAPrivateKeyMapper(1))
                .withMapper(new PasswordKeyMapper(ClearPassword.ALGORITHM_CLEAR, 2))
                .from(this.dataSource)
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport(ClearPassword.class));
        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport(PrivateKey.class));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        PrivateKey identityPrivateKey = realmIdentity.getCredential(PrivateKey.class);

        assertNotNull(identityPrivateKey);
        assertEquals(privateKey, identityPrivateKey);

        ClearPassword identityClearPassword = realmIdentity.getCredential(ClearPassword.class);

        assertNotNull(identityClearPassword);
    }

    @Test
    public void testPerAccountCredentialSupport() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = rsa.generateKeyPair();
        String userName = "john";
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        createRSAKeysTable(userName, privateKey, publicKey);
        createClearPasswordTable();

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .authenticationQuery("SELECT password FROM user_clear_password WHERE name = ?")
                    .withMapper(new PasswordKeyMapper(ClearPassword.ALGORITHM_CLEAR, 1))
                    .from(this.dataSource)
                .authenticationQuery("SELECT privateKey FROM user_rsa_keys where name = ?")
                    .withMapper(new RSAPrivateKeyMapper(1))
                    .from(this.dataSource)
                .build();

        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport(PrivateKey.class));
        assertEquals(CredentialSupport.UNKNOWN, securityRealm.getCredentialSupport(ClearPassword.class));

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity(userName);

        assertEquals(CredentialSupport.OBTAINABLE_ONLY, realmIdentity.getCredentialSupport(PrivateKey.class));
        assertEquals(CredentialSupport.UNSUPPORTED, realmIdentity.getCredentialSupport(ClearPassword.class));

        insertUserWithClearPassword(userName, "john_clear_abcd1234");

        assertEquals(CredentialSupport.FULLY_SUPPORTED, realmIdentity.getCredentialSupport(ClearPassword.class));
    }

    private void createRSAKeysTable(String userName, PrivateKey privateKey, PublicKey publicKey) {
        try {
            // RSA keys table
            Connection connection = this.dataSource.getConnection();
            Statement statement   = connection.createStatement();
            statement.executeUpdate("DROP TABLE IF EXISTS user_rsa_keys");
            statement.executeUpdate("CREATE TABLE user_rsa_keys ( id INTEGER IDENTITY, name VARCHAR(100), privateKey OTHER, publicKey OTHER)");
            statement.close();

            PreparedStatement preparedStatement = connection.prepareStatement("INSERT INTO user_rsa_keys (name, privateKey, publicKey) VALUES (?, ?, ?)");

            preparedStatement.setString(1, userName);
            preparedStatement.setBytes(2, privateKey.getEncoded());
            preparedStatement.setBytes(3, publicKey.getEncoded());
            preparedStatement.execute();
            preparedStatement.close();

            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createSaltedDigestPasswordTable(String userName, String userPassword) {
        try {
            // salted digest password table
            Connection connection = this.dataSource.getConnection();
            Statement statement  = connection.createStatement();
            statement.executeUpdate("DROP TABLE IF EXISTS user_salted_digest_password");
            statement.executeUpdate("CREATE TABLE user_salted_digest_password ( id INTEGER IDENTITY, name VARCHAR(100), digest OTHER, salt OTHER)");
            statement.close();

            byte[] salt = PasswordUtil.generateRandomSalt(BCRYPT_SALT_SIZE);
            SaltedPasswordAlgorithmSpec spac = new SaltedPasswordAlgorithmSpec(salt);
            EncryptablePasswordSpec eps = new EncryptablePasswordSpec(userPassword.toCharArray(), spac);
            PasswordFactory passwordFactory = PasswordFactory.getInstance(SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512);
            SaltedSimpleDigestPassword tsdp = (SaltedSimpleDigestPassword) passwordFactory.generatePassword(eps);

            PreparedStatement preparedStatement = connection.prepareStatement("INSERT INTO user_salted_digest_password (name, digest, salt) VALUES (?, ?, ?)");

            preparedStatement.setString(1, userName);
            preparedStatement.setBytes(2, tsdp.getDigest());
            preparedStatement.setBytes(3, tsdp.getSalt());
            preparedStatement.execute();
            preparedStatement.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createScramDigestPasswordTable(String userName, String userPassword) {
        try {
            // salted digest password table
            Connection connection = this.dataSource.getConnection();
            Statement statement  = connection.createStatement();
            statement.executeUpdate("DROP TABLE IF EXISTS user_scram_digest_password");
            statement.executeUpdate("CREATE TABLE user_scram_digest_password ( id INTEGER IDENTITY, name VARCHAR(100), digest OTHER, salt OTHER, iterationCount INTEGER)");
            statement.close();

            byte[] salt = PasswordUtil.generateRandomSalt(BCRYPT_SALT_SIZE);
            PasswordFactory factory = PasswordFactory.getInstance(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256);
            HashedPasswordAlgorithmSpec algoSpec = new HashedPasswordAlgorithmSpec(4096, salt);
            EncryptablePasswordSpec encSpec = new EncryptablePasswordSpec(userPassword.toCharArray(), algoSpec);
            ScramDigestPassword scramPassword = (ScramDigestPassword) factory.generatePassword(encSpec);
            ScramDigestPasswordSpec keySpec = factory.getKeySpec(scramPassword, ScramDigestPasswordSpec.class);

            PreparedStatement preparedStatement = connection.prepareStatement("INSERT INTO user_scram_digest_password (name, digest, salt, iterationCount) VALUES (?, ?, ?, ?)");

            preparedStatement.setString(1, userName);
            preparedStatement.setBytes(2, keySpec.getDigest());
            preparedStatement.setBytes(3, keySpec.getSalt());
            preparedStatement.setInt(4, keySpec.getIterationCount());
            preparedStatement.execute();
            preparedStatement.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createBcryptPasswordTable(String userName, String userPassword) {
        try {
            // bcrypt password table
            Connection connection = this.dataSource.getConnection();
            Statement statement = connection.createStatement();
            statement.executeUpdate("DROP TABLE IF EXISTS user_bcrypt_password");
            statement.executeUpdate("CREATE TABLE user_bcrypt_password ( id INTEGER IDENTITY, name VARCHAR(100), password VARCHAR(100))");
            statement.close();

            PreparedStatement preparedStatement = connection.prepareStatement("INSERT INTO user_bcrypt_password (name, password) VALUES (?, ?)");

            byte[] salt = PasswordUtil.generateRandomSalt(BCRYPT_SALT_SIZE);
            PasswordFactory passwordFactory = PasswordFactory.getInstance(BCryptPassword.ALGORITHM_BCRYPT);
            BCryptPassword bCryptPassword = (BCryptPassword) passwordFactory.generatePassword(
                    new EncryptablePasswordSpec(userPassword.toCharArray(), new HashedPasswordAlgorithmSpec(10, salt))
            );
            BCryptPasswordSpec bCryptPasswordSpec = passwordFactory.getKeySpec(bCryptPassword, BCryptPasswordSpec.class);

            String cryptString = PasswordUtil.getCryptString(bCryptPasswordSpec);

            preparedStatement.setString(1, userName);
            preparedStatement.setString(2, cryptString);

            preparedStatement.execute();
            preparedStatement.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createClearPasswordTable(String userName, String password) throws Exception {
        createClearPasswordTable();
        insertUserWithClearPassword(userName, password);
    }

    private void insertUserWithClearPassword(String userName, String password) throws SQLException {
        Connection connection = this.dataSource.getConnection();
        Statement statement = connection.createStatement();

        statement.executeUpdate("INSERT INTO user_clear_password (name, password) VALUES ('" + userName + "','" + password + "')");

        statement.close();
    }

    private void createClearPasswordTable() throws Exception {
        Connection connection = this.dataSource.getConnection();
        Statement statement = connection.createStatement();

        // clear text password table
        statement.executeUpdate("DROP TABLE IF EXISTS user_clear_password");
        statement.executeUpdate("CREATE TABLE user_clear_password ( id INTEGER IDENTITY, name VARCHAR(100), password VARCHAR(50))");

        statement.close();
    }
}