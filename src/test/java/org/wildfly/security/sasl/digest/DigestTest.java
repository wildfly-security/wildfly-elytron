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

package org.wildfly.security.sasl.digest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.wildfly.security.sasl.digest.DigestCallbackHandlerUtils.createClearPwdClientCallbackHandler;
import static org.wildfly.security.sasl.digest.DigestCallbackHandlerUtils.createDigestPwdClientCallbackHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.jboss.logging.Logger;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.spec.DigestPasswordSpec;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.sasl.util.UsernamePasswordHashUtil;

/**
 * A test case to test the server side of the Digest mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class DigestTest extends BaseTestCase {

    private static Logger log = Logger.getLogger(DigestTest.class);

    private static final String DIGEST = SaslMechanismInformation.Names.DIGEST_MD5;

    private static final String REALM_PROPERTY = "com.sun.security.sasl.digest.realm";

    private static final String PRE_DIGESTED_PROPERTY = "org.wildfly.security.sasl.digest.pre_digested";

    private static final String QOP_PROPERTY = "javax.security.sasl.qop";

    private static final Provider provider = new WildFlyElytronProvider();

    @BeforeClass
    public static void registerPasswordProvider() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removePasswordProvider() {
        Security.removeProvider(provider.getName());
    }

    /*
    *  Mechanism selection tests.
    */

    @Test
    public void testPolicyIndirect_Server() throws Exception {
        Map<String, Object> props = new HashMap<String, Object>();

        // If we specify DIGEST with no policy restrictions an DigestSaslServer should be returned.
        CallbackHandler serverCallback = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            }
        };
        SaslServer server = Sasl.createSaslServer(DIGEST, "TestProtocol", "TestServer", props, serverCallback);
        assertEquals(DigestSaslServer.class, server.getClass());
    }

    @Test
    public void testPolicyDirect_Server() {
        SaslServerFactory factory = obtainSaslServerFactory(DigestServerFactory.class);
        assertNotNull("SaslServerFactory not registered", factory);

        Map<String, Object> props = new HashMap<String, Object>();
        // No properties.

        String[] mechanisms = factory.getMechanismNames(props);
        assertTrue(mechanisms.length > 0); // isn't NO_MECHS
    }

    /*
     *  Normal SASL Client/Server interaction.
     */

    /**
     * Test a successful exchange using the DIGEST mechanism.
     */
    @Test
    public void testSuccessfulExchange() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");

        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword("gpwd".toCharArray())
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", "TestRealm");
        SaslClient client = Sasl.createSaslClient(new String[]{ DIGEST }, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);
        log.debug("Challenge:"+ new String(message, StandardCharsets.ISO_8859_1));
        message = client.evaluateChallenge(message);
        log.debug("Client response:"+ new String(message, StandardCharsets.ISO_8859_1));
        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }
    /**
     * Test a successful exchange using the DIGEST mechanism but the default realm.
     */
    @Test
    public void testSuccessfulExchange_DefaultRealm() throws Exception {
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword("gpwd".toCharArray())
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", null);
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);
        log.debug("Challenge:"+ new String(message, StandardCharsets.ISO_8859_1));
        message = client.evaluateChallenge(message);
        log.debug("Client response:"+ new String(message, StandardCharsets.ISO_8859_1));

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }

    /**
     * Test a successful exchange using the DIGEST mechanism but with the server side supporting an alternative protocol.
     */
    @Test
    @Ignore("ELY-91")
    public void testSuccessfulExchange_AlternativeProtocol() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put("org.wildfly.security.sasl.digest.alternative_protocols", "OtherProtocol DifferentProtocol");
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword("gpwd".toCharArray())
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", null);
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "OtherProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);
        log.debug("Challenge:"+ new String(message, StandardCharsets.UTF_8));
        message = client.evaluateChallenge(message);
        log.debug("Client response:"+ new String(message, StandardCharsets.UTF_8));

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }

    /**
     * Test that verification fails for a bad password.
     */
    @Test
    public void testBadPassword() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword("bad".toCharArray())
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", null);
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);

        message = client.evaluateChallenge(message);
        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /**
     * Test that verification fails for a bad username.
     */
    @Test
    public void testBadUsername() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("Borris")
                .setPassword("gpwd".toCharArray())
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", null);
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);

        message = client.evaluateChallenge(message);
        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /**
     * Test that verification fails for a bad realm.
     */
    @Test
    public void testBadRealm() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");

        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword("gpwd".toCharArray())
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", "BadRealm");

        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);

        message = client.evaluateChallenge(message);
        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /**
     * Test a successful exchange with realm selection.
     */
    @Test
    public void testRealmSelection() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, DigestServerFactory.realmsArrayToProperty(new String[] { "realm1", "second realm", "last\\ " }));
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword("gpwd".toCharArray())
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", "last\\ ");
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);
        log.debug("Challenge:"+ new String(message, StandardCharsets.ISO_8859_1));
        message = client.evaluateChallenge(message);
        log.debug("Client response:" + new String(message, StandardCharsets.ISO_8859_1));
        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }

    /*
     *  Repeat of the above tests but with pre-hashed passwords - server side.
     */

    /**
     * Test a successful exchange using the DIGEST mechanism with a pre-hashed password.
     */
    @Test
    public void testSuccessfulExchange_PreHashedServer() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        serverProps.put(PRE_DIGESTED_PROPERTY, "true");
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword(DigestPassword.ALGORITHM_DIGEST_MD5, getDigestKeySpec("George", "gpwd", "TestRealm"))
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", null);
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);
        log.debug("Challenge:"+ new String(message, StandardCharsets.ISO_8859_1));
        message = client.evaluateChallenge(message);
        log.debug("Client response:"+ new String(message, StandardCharsets.ISO_8859_1));
        message = server.evaluateResponse(message);
        log.debug("Server response:"+ new String(message, StandardCharsets.ISO_8859_1));
        client.evaluateChallenge(message);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }

    /**
     * Test a successful exchange using the DIGEST mechanism but the default realm with a pre-hashed password.
     */
    @Test
    public void testSuccessfulExchange_DefaultRealm_PreHashedServer() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(PRE_DIGESTED_PROPERTY, "true");
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword(DigestPassword.ALGORITHM_DIGEST_MD5, getDigestKeySpec("George", "gpwd", "TestServer"))
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", null);

        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);
        log.debug("Challenge:"+ new String(message, StandardCharsets.ISO_8859_1));
        message = client.evaluateChallenge(message);
        log.debug("Client response:" + new String(message, StandardCharsets.ISO_8859_1));
        message = server.evaluateResponse(message);
        log.debug("Server response:"+ new String(message, StandardCharsets.ISO_8859_1));
        client.evaluateChallenge(message);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }

    /**
     * Test that verification fails for a bad password with a pre-hashed password.
     */
    @Test
    public void testBadPassword_PreHashedServer() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        serverProps.put(PRE_DIGESTED_PROPERTY, "true");
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword(DigestPassword.ALGORITHM_DIGEST_MD5, getDigestKeySpec("George", "gpwd", "TestRealm"))
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "bad", null);
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);
        log.debug("Challenge:" + new String(message, StandardCharsets.ISO_8859_1));
        message = client.evaluateChallenge(message);
        log.debug("Client response:" + new String(message, StandardCharsets.ISO_8859_1));
        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }


    /**
     * Test that verification fails for a bad username with a pre-hashed password.
     */
    @Test
    public void testBadUsername_PreHashedServer() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(PRE_DIGESTED_PROPERTY, "true");
        serverProps.put(REALM_PROPERTY, "TestRealm");
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("Borris")
                .setPassword(DigestPassword.ALGORITHM_DIGEST_MD5, getDigestKeySpec("George", "gpwd", "TestRealm"))
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "bad", null);
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);
        log.debug("Challenge:" + new String(message, StandardCharsets.ISO_8859_1));
        message = client.evaluateChallenge(message);
        log.debug("Client response:" + new String(message, StandardCharsets.ISO_8859_1));
        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /**
     * Test that verification fails for a bad realm with a pre-hashed password
     */
    @Test
    public void testBadRealm_PreHashedServer() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        serverProps.put(PRE_DIGESTED_PROPERTY, "true");
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword(DigestPassword.ALGORITHM_DIGEST_MD5, getDigestKeySpec("George", "gpwd", "TestRealm"))
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", "BadRealm");
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);
        log.debug("Challenge:" + new String(message, StandardCharsets.ISO_8859_1));
        message = client.evaluateChallenge(message);
        log.debug("Client response:" + new String(message, StandardCharsets.ISO_8859_1));
        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /*
     *  Repeat of the above tests but with pre-hashed passwords - client side.
     */

    /**
     * Test a successful exchange using the DIGEST mechanism with a pre-hashed password.
     */
    @Test
    public void testSuccessfulExchange_PreHashedClient() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");

        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword(DigestPassword.ALGORITHM_DIGEST_MD5, getDigestKeySpec("George", "gpwd", "TestRealm"))
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createDigestPwdClientCallbackHandler("George", "gpwd", "TestRealm", null);

        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(PRE_DIGESTED_PROPERTY, "true");

        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", clientProps, clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);

        message = client.evaluateChallenge(message);
        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }

    /**
     * Test a successful exchange using the DIGEST mechanism but the default realm with a pre-hashed password.
     */
    @Test
    public void testSuccessfulExchange_DefaultRealm_PreHashedClient() throws Exception {
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword(DigestPassword.ALGORITHM_DIGEST_MD5, getDigestKeySpec("George", "gpwd", "TestServer"))
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();


        CallbackHandler clientCallback = createDigestPwdClientCallbackHandler("George", "gpwd", "TestServer", null);
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(PRE_DIGESTED_PROPERTY, "true");
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", clientProps, clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);
        message = client.evaluateChallenge(message);

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }

    /**
     * Test that verification fails for a bad password with a pre-hashed password.
     */
    @Test
    public void testBadPassword_PreHashedClient() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword(DigestPassword.ALGORITHM_DIGEST_MD5, getDigestKeySpec("George", "gpwd", "TestRealm"))
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createDigestPwdClientCallbackHandler("George", "bad", "TestRealm", null);
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(PRE_DIGESTED_PROPERTY, "true");

        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", clientProps, clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);

        message = client.evaluateChallenge(message);
        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /**
     * Test that verification fails for a bad username with a pre-hashed password.
     */
    @Test
    public void testBadUsername_PreHashedClient() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword(DigestPassword.ALGORITHM_DIGEST_MD5, getDigestKeySpec("George", "gpwd", "TestRealm"))
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createDigestPwdClientCallbackHandler("Borris", "gpwd", "TestRealm", null);
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(PRE_DIGESTED_PROPERTY, "true");
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", clientProps, clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);

        message = client.evaluateChallenge(message);
        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /**
     * Test that verification fails for a bad realm with a pre-hashed password
     */
    @Test
    public void testBadRealm_PreHashedClient() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword(DigestPassword.ALGORITHM_DIGEST_MD5, getDigestKeySpec("George", "gpwd", "TestRealm"))
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createDigestPwdClientCallbackHandler("George", "gpwd", "BadRealm", "BadRealm");

        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(PRE_DIGESTED_PROPERTY, "true");
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", clientProps, clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);

        message = client.evaluateChallenge(message);
        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /**
     * Test a successful exchange with integrity check
     */
    @Test
    public void testSuccessfulExchangeWithIntegrityCheck() throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(QOP_PROPERTY, "auth-int");
        serverProps.put(WildFlySasl.SUPPORTED_CIPHER_NAMES, "des,3des,rc4,rc4-40,rc4-56");

        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword("gpwd".toCharArray())
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", null);
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-int");
        clientProps.put(WildFlySasl.SUPPORTED_CIPHER_NAMES, "des,3des,rc4,rc4-40,rc4-56");
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", clientProps, clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = new byte[0];
        message = server.evaluateResponse(message);
        message = client.evaluateChallenge(message);
        message = server.evaluateResponse(message);
        message = client.evaluateChallenge(message);
        assertTrue(client.isComplete());
        assertTrue(server.isComplete());
        assertEquals("George", server.getAuthorizationID());

        message = server.wrap(new byte[]{0x12,0x34,0x56}, 0, 3);
        Assert.assertArrayEquals(new byte[]{0x12,0x34,0x56}, client.unwrap(message, 0, message.length));

        message = client.wrap(new byte[]{(byte)0xAB,(byte)0xCD,(byte)0xEF}, 0, 3);
        Assert.assertArrayEquals(new byte[]{(byte)0xAB,(byte)0xCD,(byte)0xEF}, server.unwrap(message, 0, message.length));
    }


    /**
     * Test a successful exchange with privacy protection
     */
    @Test
    public void testSuccessfulExchangeWithPrivacyProtection() throws Exception {
        testSuccessulExchangeWithPrivacyProtection("3des");
        testSuccessulExchangeWithPrivacyProtection("des");
        testSuccessulExchangeWithPrivacyProtection("rc4");
        testSuccessulExchangeWithPrivacyProtection("rc4-40");
        testSuccessulExchangeWithPrivacyProtection("rc4-56");
    }

    private void testSuccessulExchangeWithPrivacyProtection(String clientCipher)throws Exception {
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(QOP_PROPERTY, "auth-conf");
        serverProps.put(WildFlySasl.SUPPORTED_CIPHER_NAMES, "des,3des,rc4,rc4-40,rc4-56");
        SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                .setUserName("George")
                .setPassword("gpwd".toCharArray())
                .setProperties(serverProps)
                .setProtocol("TestProtocol")
                .setServerName("TestServer")
                .build();

        CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", null);
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        clientProps.put(WildFlySasl.SUPPORTED_CIPHER_NAMES, clientCipher);
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", clientProps, clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = new byte[0];
        message = server.evaluateResponse(message);
        message = client.evaluateChallenge(message);
        message = server.evaluateResponse(message);
        message = client.evaluateChallenge(message);
        assertTrue(client.isComplete());
        assertTrue(server.isComplete());
        assertEquals("George", server.getAuthorizationID());

        message = server.wrap(new byte[]{0x12,0x34,0x56}, 0, 3);
        Assert.assertArrayEquals(new byte[]{0x12,0x34,0x56}, client.unwrap(message, 0, message.length));

        message = client.wrap(new byte[]{(byte)0xAB,(byte)0xCD,(byte)0xEF}, 0, 3);
        Assert.assertArrayEquals(new byte[]{(byte)0xAB,(byte)0xCD,(byte)0xEF}, server.unwrap(message, 0, message.length));
    }

    private KeySpec getDigestKeySpec(String username, String password, String realm) throws NoSuchAlgorithmException {
        byte[] urpHash = new UsernamePasswordHashUtil().generateHashedURP(username, realm, password.toCharArray());
        return new DigestPasswordSpec(username, realm, urpHash);
    }


}
