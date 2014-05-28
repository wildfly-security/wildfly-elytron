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

import static javax.security.sasl.Sasl.POLICY_NOANONYMOUS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.wildfly.sasl.anonymous.AnonymousClientFactory;
import org.wildfly.sasl.anonymous.AnonymousSaslClient;
import org.wildfly.sasl.anonymous.AnonymousSaslServer;
import org.wildfly.sasl.anonymous.AnonymousServerFactory;

/**
 * Test for the Anonymous SASL mechanism, this will test both the client and server side.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AnonymousTest extends BaseTestCase {

    private static final String ANONYMOUS = "ANONYMOUS";

    /*
     *  Mechanism selection tests.
     */

    @Test
    public void testPolicyIndirect_Server() throws Exception {
        Map<String, Object> props = new HashMap<String, Object>();

        // If we specify ANONYMOUS with no policy restrictions an AnonymousSaslServer should be returned.
        SaslServer server = Sasl.createSaslServer(ANONYMOUS, "TestProtocol", "TestServer", props, null);
        assertEquals(AnonymousSaslServer.class, server.getClass());

        // If we specify no anonymous even though we specify ANONYMOUS as the mechanism no server should be
        // returned.
        props.put(Sasl.POLICY_NOANONYMOUS, true);
        server = Sasl.createSaslServer(ANONYMOUS, "TestProtocol", "TestServer", props, null);
        assertNull(server);
    }

    @Test
    public void testPolicyIndirect_Client() throws Exception {
        Map<String, Object> props = new HashMap<String, Object>();

        // If we specify ANONYMOUS with no policy restrictions an PlainSaslServer should be returned.
        SaslClient client = Sasl.createSaslClient(new String[]{ANONYMOUS}, "TestUser", "TestProtocol", "TestServer", props, null);
        assertEquals(AnonymousSaslClient.class, client.getClass());

        // If we specify no plain text even though we specify PLAIN as the mechanism no server should be
        // returned.
        props.put(Sasl.POLICY_NOANONYMOUS, true);
        client = Sasl.createSaslClient(new String[]{ANONYMOUS}, "TestUser", "TestProtocol", "TestServer", props, null);
        assertNull(client);
    }


    @Test
    public void testPolicyDirect_Server() {
        SaslServerFactory factory = obtainSaslServerFactory(AnonymousServerFactory.class);
        assertNotNull("SaslServerFactory not registered", factory);

        String[] mechanisms;
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties.
        mechanisms = factory.getMechanismNames(props);
        assertSingleMechanism(ANONYMOUS, mechanisms);

        // Request No Anonymous
        props.put(POLICY_NOANONYMOUS, true);
        mechanisms = factory.getMechanismNames(props);
        assertNoMechanisms(mechanisms);
    }

    @Test
    public void testPolicyDirect_Client() {
        SaslClientFactory factory = obtainSaslClientFactory(AnonymousClientFactory.class);
        assertNotNull("SaslClientFactory not registered", factory);

        String[] mechanisms;
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties.
        mechanisms = factory.getMechanismNames(props);
        assertSingleMechanism(ANONYMOUS, mechanisms);

        // Request No Anonymous
        props.put(POLICY_NOANONYMOUS, true);
        mechanisms = factory.getMechanismNames(props);
        assertNoMechanisms(mechanisms);
    }


    /*
     *  Normal SASL Client/Server interaction.
     */

    /**
     * Test a successful exchange using the ANONYMOUS mechanism.
     */

    @Test
    public void testSuccessfulExchange() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", (char[]) null);
        SaslServer server = Sasl.createSaslServer(ANONYMOUS, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", (char[]) null);
        SaslClient client = Sasl.createSaslClient(new String[]{ANONYMOUS}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("anonymous", server.getAuthorizationID());
    }

}
