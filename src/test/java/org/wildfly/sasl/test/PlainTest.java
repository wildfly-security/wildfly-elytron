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
package org.wildfly.sasl.test;

import static javax.security.sasl.Sasl.POLICY_NOPLAINTEXT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.wildfly.sasl.plain.PlainSaslServer;
import org.wildfly.sasl.plain.PlainServerFactory;

/**
 * Test the server side of the Plain SASL mecanism.
 * <p/>
 * (The client side is provided by the JDK so this test case will be testing interoperability
 * with the JDK supplied implementation)
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PlainTest extends BaseTestCase {

    private static final String PLAIN = "PLAIN";

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
        props.put(Sasl.POLICY_NOPLAINTEXT, true);
        server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", props, null);
        assertNull(server);
    }

    @Test
    public void testPolicyDirect() {
        SaslServerFactory factory = obtainSaslServerFactory(PlainServerFactory.class);
        assertNotNull("SaslServerFactory not registered", factory);

        String[] mechanisms;
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties.
        mechanisms = factory.getMechanismNames(props);
        assertSingleMechanism(PLAIN, mechanisms);

        // Request No Plain Text
        props.put(POLICY_NOPLAINTEXT, true);
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
        CallbackHandler serverCallback = new ServerCallbackHandler("George", "gpwd".toCharArray());
        SaslServer server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", "gpwd".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }

    /**
     * Test that an exchange involving a bad password is correctly rejected.
     */
    @Test
    public void testBadPassword() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", "bad".toCharArray());
        SaslServer server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", "gpwd".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /**
     * Test that an exchange involving a bad username is correctly rejected.
     */
    @Test
    public void testBadUsername() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("Borris", "gpwd".toCharArray());
        SaslServer server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", "gpwd".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /**
     * Test a successful exchange using the PLAIN mechanism where no Authorization ID is specified.
     */
    @Test
    public void testSuccessfulExchange_NoAuthorization() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", "gpwd".toCharArray());
        SaslServer server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", "gpwd".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{PLAIN}, null, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }


}
