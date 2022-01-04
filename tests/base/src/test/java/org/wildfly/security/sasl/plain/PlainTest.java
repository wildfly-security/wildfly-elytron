/*
 * JBoss, Home of Professional Open Source.
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
package org.wildfly.security.sasl.plain;

import static javax.security.sasl.Sasl.POLICY_NOPLAINTEXT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.wildfly.security.password.interfaces.BCryptPassword.BCRYPT_SALT_SIZE;
import static org.wildfly.security.sasl.test.SaslTestUtil.assertNoMechanisms;
import static org.wildfly.security.sasl.test.SaslTestUtil.assertSingleMechanism;
import static org.wildfly.security.sasl.test.SaslTestUtil.obtainSaslServerFactory;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.hsqldb.jdbc.JDBCDataSource;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.spec.Encoding;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedHashPasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.test.SaslServerBuilder;

/**
 * Test the server side of the Plain SASL mechanism.
 * <p/>
 * (The client side is provided by the JDK so this test case will be testing interoperability
 * with the JDK supplied implementation)
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
// has dependency on wildfly-elytron-client
public class PlainTest {

    private static final String PLAIN = "PLAIN";

    private static final Provider[] providers = new Provider[] {
            WildFlyElytronSaslPlainProvider.getInstance(),
            WildFlyElytronPasswordProvider.getInstance()
    };

    @ClassRule
    public static final DataSourceRule dataSourceRule = new DataSourceRule();

    @BeforeClass
    public static void registerProvider() {
        for (Provider provider : providers) {
            Security.insertProviderAt(provider, 1);
        }
    }

    @AfterClass
    public static void removeProvider() {
        for (Provider provider : providers) {
            Security.removeProvider(provider.getName());
        }
    }

    /*
     *  Mechanism selection tests.
     */

    @Test
    public void testPolicyIndirect() throws Exception {
        Map<String, Object> props = new HashMap<String, Object>();

        // If we specify PLAIN with no policy restrictions an PlainSaslServer should be returned.
        SaslServer server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", props, null);
        assertEquals(PlainSaslServer.class, server.getClass());

        // If we specify no plain text even though we specify PLAIN as the mechanism no server should be
        // returned.
        props.put(Sasl.POLICY_NOPLAINTEXT, Boolean.toString(true));
        server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", props, null);
        assertNull(server);
    }

    @Test
    public void testPolicyDirect() {
        SaslServerFactory factory = obtainSaslServerFactory(PlainSaslServerFactory.class);
        assertNotNull("SaslServerFactory not registered", factory);

        String[] mechanisms;
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties.
        mechanisms = factory.getMechanismNames(props);
        assertSingleMechanism(PLAIN, mechanisms);

        // Request No Plain Text
        props.put(POLICY_NOPLAINTEXT, Boolean.toString(true));
        mechanisms = factory.getMechanismNames(props);
        assertNoMechanisms(mechanisms);
    }

    /*
     *  Normal SASL Client/Server interaction.
     */

    /**
     * Test a successful exchange using the PLAIN mechanism.
     */
    @Test
    public void testSuccessfulExchange() throws Exception {
        SaslServer server = createSaslServer("George", "gpwd".toCharArray());

        testExchange(server, "George", "gpwd");
    }

    /**
     * Test a successful exchange using the PLAIN mechanism and Hex Encoding in the FileSystem Realm
     */
    @Test
    public void testSuccessfulExchange_FileSystemRealm_HexEncoding() throws Exception {
        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setUserName("George")
                .setPassword("gpwd".toCharArray())
                .setModifiableRealm()
                .setHashEncoding(Encoding.HEX)
                .build();

        testExchange(server,"George", "gpwd");
    }

    /**
     * Test a successful exchange using the PLAIN mechanism and a different Character set
     * for the password in the FileSystem Realm using a BCRYPT password
     */
    @Test
    public void testSuccessfulExchange_FileSystemRealm_BcryptCharset() throws Exception {

        char[] actualPassword = "password密码".toCharArray();
        EncryptablePasswordSpec spec = new EncryptablePasswordSpec(actualPassword,
                new IteratedSaltedPasswordAlgorithmSpec(10, generateRandomSalt(BCRYPT_SALT_SIZE)),
                Charset.forName("gb2312"));

        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setUserName("George")
                .setPassword(BCryptPassword.ALGORITHM_BCRYPT, spec)
                .setModifiableRealm()
                .setHashCharset(Charset.forName("gb2312"))
                .build();

        testExchange(server, "George", "password密码");

    }

    /**
     * Test a successful exchange using the PLAIN mechanism and a different Character set
     * for the password in the FileSystem Realm using a SCRAM password
     */
    @Test
    public void testSuccessfulExchange_FileSystemRealm_ScramCharset() throws Exception {

        char[] actualPassword = "passwordHyväää".toCharArray();
        EncryptablePasswordSpec spec = new EncryptablePasswordSpec(actualPassword,
                new IteratedSaltedPasswordAlgorithmSpec(4096, generateRandomSalt(BCRYPT_SALT_SIZE)),
                Charset.forName("ISO-8859-1"));

        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setUserName("George")
                .setPassword(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256, spec)
                .setModifiableRealm()
                .setHashCharset(Charset.forName("ISO-8859-1"))
                .build();

        testExchange(server, "George", "passwordHyväää");

    }

    /**
     * Test a successful exchange using the PLAIN mechanism and a different Character set
     * for the password in the FileSystem Realm using a Simple DIGEST password
     */
    @Test
    public void testSuccessfulExchange_FileSystemRealm_SimpleDigestCharset() throws Exception {

        char[] actualPassword = "пароль".toCharArray();
        EncryptablePasswordSpec spec = new EncryptablePasswordSpec(actualPassword, null,
                Charset.forName("KOI8-R"));

        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setUserName("George")
                .setPassword(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512, spec)
                .setModifiableRealm()
                .setHashCharset(Charset.forName("KOI8-R"))
                .build();

        testExchange(server, "George", "пароль");

    }

    /**
     * Test a successful exchange using the PLAIN mechanism and a different Character set
     * for the password in the FileSystem Realm using a Simple Salted DIGEST password
     */
    @Test
    public void testSuccessfulExchange_FileSystemRealm_SimpleSaltedDigestCharset() throws Exception {

        char[] actualPassword = "пароль".toCharArray();
        EncryptablePasswordSpec spec = new EncryptablePasswordSpec(actualPassword,
                new SaltedPasswordAlgorithmSpec(generateRandomSalt(BCRYPT_SALT_SIZE)),
                Charset.forName("KOI8-R"));

        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setUserName("George")
                .setPassword(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, spec)
                .setModifiableRealm()
                .setHashCharset(Charset.forName("KOI8-R"))
                .build();

        testExchange(server, "George", "пароль");

    }

    /**
     * Test a successful exchange using the PLAIN mechanism and Hex Encoding in the LegacyPropertiesSecurityRealm
     */
    @Test
    public void testSuccessfulExchange_LegacySecurityRealm_HexEncoding() throws Exception {
        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setUserName("elytron2")
                .setRealmName("ManagementRealm")
                .setDefaultRealmName("ManagementRealm")
                .setPlainText(true)
                .setLegacyInputStream(this.getClass().getResourceAsStream("charset.properties"))
                .setHashEncoding(Encoding.HEX)
                .build();

        testExchange(server, "elytron2", "passwd12#$");
    }

    /**
     * Test a successful exchange using the PLAIN mechanism and different
     * character set in the LegacyPropertiesSecurityRealm and HEX encoding
     * using a DIGEST password
     */
    @Test
    public void testSuccessfulExchange_LegacySecurityRealm_DigestCharset() throws Exception {
        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setUserName("elytron")
                .setRealmName("ManagementRealm")
                .setDefaultRealmName("ManagementRealm")
                .setLegacyInputStream(this.getClass().getResourceAsStream("charset.properties"))
                .setHashCharset(Charset.forName("gb2312"))
                .setHashEncoding(Encoding.HEX)
                .build();

        testExchange(server, "elytron", "password密码");
    }

    /**
     * Test a successful exchange using the PLAIN mechanism and different character set
     * in the JDBC Security realm and BASE64 encoding using a BCRYPT Password
     */
    @Test
    public void testSuccessfulExchange_JdbcRealm_BcryptCharset() throws Exception {
        createEncryptTableWithSaltAndIteration("George", "passwordHyväää",
                10, Charset.forName("ISO-8859-1"), "user_bcrypt_encoded_password", BCryptPassword.ALGORITHM_BCRYPT);

        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setMapperAlgorithm(BCryptPassword.ALGORITHM_BCRYPT)
                .setPrincipalQuery("SELECT password, salt, iterationCount FROM user_bcrypt_encoded_password where name = ?")
                .setDataSource(dataSourceRule.getDataSource())
                .setHashCharset(Charset.forName("ISO-8859-1"))
                .build();

        testExchange(server, "George", "passwordHyväää");

    }

    /**
     * Test a successful exchange using the PLAIN mechanism and different character set
     * in the JDBC Security realm and BASE64 encoding using a SCRAM Password
     */
    @Test
    public void testSuccessfulExchange_JdbcRealm_ScramCharset() throws Exception {
        createEncryptTableWithSaltAndIteration("George", "passwordHyväää",
                4096, Charset.forName("ISO-8859-1"), "user_scram_digest_password", ScramDigestPassword.ALGORITHM_SCRAM_SHA_256);

        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setMapperAlgorithm(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256)
                .setPrincipalQuery("SELECT password, salt, iterationCount FROM user_scram_digest_password where name = ?")
                .setDataSource(dataSourceRule.getDataSource())
                .setHashCharset(Charset.forName("ISO-8859-1"))
                .build();

        testExchange(server, "George", "passwordHyväää");
    }

    /**
     * Test a successful exchange using the PLAIN mechanism and different character set
     * in the JDBC Security realm and BASE64 encoding using a Simple DIGEST Password
     */
    @Test
    public void testSuccessfulExchange_JdbcRealm_SimpleDigestCharset() throws Exception {
        createSimpleDigestPasswordTable(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512,
                "George", "password密码", Charset.forName("gb2312"));

        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setMapperAlgorithm(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512)
                .setPrincipalQuery("SELECT digest FROM user_simple_digest_password where name = ?")
                .setDataSource(dataSourceRule.getDataSource())
                .setHashCharset(Charset.forName("gb2312"))
                .build();

        testExchange(server, "George", "password密码");
    }

    /**
     * Test a successful exchange using the PLAIN mechanism and different character set
     * in the JDBC Security realm and BASE64 encoding using a Simple Salted DIGEST Password
     */
    @Test
    public void testSuccessfulExchange_JdbcRealm_SimpleSaltedDigestCharset() throws Exception {

        createSimpleSaltedDigestTable("George", "password密码", Charset.forName("gb2312"));

        SaslServer server = new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setMapperAlgorithm(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512)
                .setPrincipalQuery("SELECT digest, salt FROM user_salted_simple_digest_password where name = ?")
                .setDataSource(dataSourceRule.getDataSource())
                .setHashCharset(Charset.forName("gb2312"))
                .build();

        testExchange(server, "George", "password密码");
    }



    /**
     * Test that an exchange involving a bad password is correctly rejected.
     */
    @Test
    public void testBadPassword() throws Exception {
        SaslServer server = createSaslServer("George", "gpwd".toCharArray());

        CallbackHandler clientCallback = createClientCallbackHandler("George", "bad".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);
        assertEquals("George\0George\0bad",new String(message, StandardCharsets.UTF_8));

        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {}

        // server is complete even if an exception is thrown.  Ref: JDK
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
    }

    /**
     * Test that an exchange involving a bad username is correctly rejected.
     */
    @Test
    public void testBadUsername() throws Exception {
        SaslServer server = createSaslServer("Borris", "gpwd".toCharArray());

        CallbackHandler clientCallback = createClientCallbackHandler("George", "gpwd".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);
        assertEquals("George\0George\0gpwd", new String(message, StandardCharsets.UTF_8));

        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {}

        // server is complete even if an exception is thrown.  Ref: JDK
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
    }

    /**
     * Test a successful exchange using the PLAIN mechanism where no Authorization ID is specified.
     */
    @Test
    public void testSuccessfulExchange_NoAuthorization() throws Exception {
        SaslServer server = createSaslServer("George", "gpwd".toCharArray());

        CallbackHandler clientCallback = createClientCallbackHandler("George", "gpwd".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, null, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);
        assertEquals("\0George\0gpwd",new String(message, StandardCharsets.UTF_8));

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }

    /**
     * Test that an exchange involving a disallowed authorization ID is correctly rejected.
     */
    @Test
    public void testSuccessfulExchange_DifferentAuthorizationID() throws Exception {
        SaslServer server = createSaslServer("George", "gpwd".toCharArray());

        CallbackHandler clientCallback = createClientCallbackHandler("George", "gpwd".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, "Borris", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);
        assertEquals("Borris\0George\0gpwd",new String(message, StandardCharsets.UTF_8));

        try {
            server.evaluateResponse(message);
            fail("Exception not thrown.");
        } catch (IOException e) {
        }

        // server is complete even if an exception is thrown.  Ref: JDK
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
    }

    /**
     * Test a successful exchange using the PLAIN mechanism and a non-normalized password.
     */
    @Test
    public void testSuccessfulExchange_NoNormalization() throws Exception {
        String username = "George\u00A8";
        String password = "password\u00A8";
        SaslServer server = createSaslServer(username, password.toCharArray());

        CallbackHandler clientCallback = createClientCallbackHandler(username, password.toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, username, "TestProtocol", "TestServer", Collections.singletonMap(WildFlySasl.SKIP_NORMALIZATION, "true"), clientCallback);

        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);
        assertEquals(username + "\0" +  username +  "\0" + password, new String(message, StandardCharsets.UTF_8));

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals(username, server.getAuthorizationID());
    }

    /**
     * Test a successful exchange using minimal maximum allowed length of credentials - 255B
     */
    @Test
    public void testMaximumLength() throws Exception {
        SaslServer server = createSaslServer("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".toCharArray());

        CallbackHandler clientCallback = createClientCallbackHandler("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);
        assertEquals("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",new String(message, StandardCharsets.UTF_8));
        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", server.getAuthorizationID());
    }

    private void createSimpleSaltedDigestTable(String username, String password, Charset hashCharset) throws Exception {
        try (
                Connection connection = dataSourceRule.getDataSource().getConnection();
                Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DROP TABLE IF EXISTS user_salted_simple_digest_password");
            statement.executeUpdate("CREATE TABLE user_salted_simple_digest_password ( id INTEGER IDENTITY, name VARCHAR(100), digest VARCHAR(100), salt OTHER)");
        }

        try (
                Connection connection = dataSourceRule.getDataSource().getConnection();
                PreparedStatement  preparedStatement = connection.prepareStatement("INSERT INTO user_salted_simple_digest_password (name, digest, salt) VALUES (?, ?, ?)");
        ) {
            byte[] salt = generateRandomSalt(BCRYPT_SALT_SIZE);
            EncryptablePasswordSpec eps = new EncryptablePasswordSpec(password.toCharArray(), new
                    SaltedPasswordAlgorithmSpec(salt), hashCharset);
            PasswordFactory passwordFactory = PasswordFactory.getInstance(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512);
            SaltedSimpleDigestPassword saltedPassword = (SaltedSimpleDigestPassword) passwordFactory.generatePassword(eps);

            preparedStatement.setString(1, username);
            preparedStatement.setString(2, ByteIterator.ofBytes(saltedPassword.getDigest()).base64Encode().drainToString());
            preparedStatement.setBytes(3, saltedPassword.getSalt());
            preparedStatement.execute();
        }
    }

    private SimpleDigestPassword createSimpleDigestPasswordTable(String algorithm, String username, String password,
                                                                 Charset hashCharset) throws Exception {
        try (
                Connection connection = dataSourceRule.getDataSource().getConnection();
                Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DROP TABLE IF EXISTS user_simple_digest_password");
            statement.executeUpdate("CREATE TABLE user_simple_digest_password ( id INTEGER IDENTITY, name VARCHAR(100), digest VARCHAR(100))");
        }

        try (
                Connection connection = dataSourceRule.getDataSource().getConnection();
                PreparedStatement  preparedStatement = connection.prepareStatement("INSERT INTO user_simple_digest_password (name, digest) VALUES (?, ?)");
        ) {
            EncryptablePasswordSpec eps = new EncryptablePasswordSpec(password.toCharArray(), null, hashCharset);
            PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
            SimpleDigestPassword tsdp = (SimpleDigestPassword) passwordFactory.generatePassword(eps);

            preparedStatement.setString(1, username);
            preparedStatement.setString(2, ByteIterator.ofBytes(tsdp.getDigest()).base64Encode().drainToString());
            preparedStatement.execute();

            return tsdp;
        }
    }

    private void createEncryptTableWithSaltAndIteration(String username, String password, int iterationCount,
                                                        Charset hashCharset, String tableName, String algorithm) throws Exception {
        try (
                Connection connection = dataSourceRule.getDataSource().getConnection();
                Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DROP TABLE IF EXISTS " + tableName);
            statement.executeUpdate("CREATE TABLE " + tableName + " ( id INTEGER IDENTITY, name VARCHAR(100), password VARCHAR(100), salt OTHER, iterationCount INTEGER)");
        }

        try (
                Connection connection = dataSourceRule.getDataSource().getConnection();
                PreparedStatement  preparedStatement = connection.prepareStatement("INSERT INTO " + tableName + " (name, password, salt, iterationCount) VALUES (?, ?, ?, ?)");
        ) {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
            EncryptablePasswordSpec spec = new EncryptablePasswordSpec(password.toCharArray(),
                    new IteratedSaltedPasswordAlgorithmSpec(iterationCount, generateRandomSalt(BCRYPT_SALT_SIZE)),
                    hashCharset);

            preparedStatement.setString(1, username);

            if (algorithm.equals(BCryptPassword.ALGORITHM_BCRYPT)) {
                BCryptPassword bcryptPassword = (BCryptPassword) passwordFactory.generatePassword(spec);
                preparedStatement.setString(2, ByteIterator.ofBytes(bcryptPassword.getHash()).base64Encode().drainToString());
                preparedStatement.setBytes(3, bcryptPassword.getSalt());
                preparedStatement.setInt(4, bcryptPassword.getIterationCount());
            } else {
                // its scram digest
                ScramDigestPassword scramPassword = (ScramDigestPassword) passwordFactory.generatePassword(spec);
                IteratedSaltedHashPasswordSpec keySpec = passwordFactory.getKeySpec(scramPassword, IteratedSaltedHashPasswordSpec.class);
                preparedStatement.setString(2, ByteIterator.ofBytes(keySpec.getHash()).base64Encode().drainToString());
                preparedStatement.setBytes(3, keySpec.getSalt());
                preparedStatement.setInt(4, keySpec.getIterationCount());
            }

            preparedStatement.execute();
        }
    }

    private void testExchange(SaslServer server, String username, String password) throws Exception {

        CallbackHandler clientCallback = createClientCallbackHandler(username, password.toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, username, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals(username, server.getAuthorizationID());

    }

    private static byte[] generateRandomSalt(int saltSize) {
        byte[] randomSalt = new byte[saltSize];
        ThreadLocalRandom.current().nextBytes(randomSalt);
        return randomSalt;
    }

    private SaslServer createSaslServer(final String expectedUsername, final char[] expectedPassword) throws Exception {
        return new SaslServerBuilder(PlainSaslServerFactory.class, PLAIN)
                .setUserName(expectedUsername)
                .setPassword(expectedPassword)
                .build();
  }

    private CallbackHandler createClientCallbackHandler(final String username, final char[] password) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.empty()
                                .useName(username)
                                .usePassword(password)
                                .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism(PLAIN)));


        return ClientUtils.getCallbackHandler(new URI("doesnot://matter?"), context);
    }

    static class DataSourceRule implements TestRule {
        private JDBCDataSource dataSource;

        @Override
        public org.junit.runners.model.Statement apply(org.junit.runners.model.Statement current, Description description) {
            return new org.junit.runners.model.Statement() {

                @Override
                public void evaluate() throws Throwable {
                    dataSource = new JDBCDataSource();
                    dataSource.setDatabase("mem:elytron-jdbc-realm-test");
                    dataSource.setUser("sa");
                    try {
                        current.evaluate();
                    } catch (Exception e) {
                        throw e;
                    }
                }
            };
        }

        public JDBCDataSource getDataSource() {
            return dataSource;
        }
    }
}
