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

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronPasswordProvider;
import org.wildfly.security.WildFlyElytronSaslPlainProvider;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.test.BaseTestCase;
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
public class PlainTest extends BaseTestCase {

    private static final String PLAIN = "PLAIN";

    private static final Provider[] providers = new Provider[] {
            WildFlyElytronSaslPlainProvider.getInstance(),
            WildFlyElytronPasswordProvider.getInstance()
    };

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

        CallbackHandler clientCallback = createClientCallbackHandler("George", "gpwd".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);
        assertEquals("George\0George\0gpwd",new String(message, StandardCharsets.UTF_8));

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("George", server.getAuthorizationID());
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
}
