/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.sasl.test;

import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.jboss.sasl.util.Charsets;
import org.junit.Test;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

/**
 * Test for the local user SASL mechanism, this will test both the client and server side.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class LocalUserTest extends BaseTestCase {

    private static final String LOCAL_USER = "JBOSS-LOCAL-USER";
    
    /*
     *  Normal SASL Client/Server interaction - Client First
     */

    /**
     * Test a successful exchange using the JBOSS-LOCAL-USER mechanism.
     */

    @Test
    public void testSuccessfulExchange_CF() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", (char[]) null);
        SaslServer server = Sasl.createSaslServer(LOCAL_USER, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", (char[]) null);
        SaslClient client = Sasl.createSaslClient(new String[]{ LOCAL_USER }, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] response = client.evaluateChallenge(new byte[0]);
        byte[] challenge = server.evaluateResponse(response);
        response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        assertNull(challenge);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }
    
    /**
     * Test a successful exchange using the JBOSS-LOCAL-USER mechanism with quiet client side
     * and default user server side.
     */

    @Test
    public void testSuccessfulQuietExchange_CF() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("$local", (char[]) null);
        Map<String, String> serverOptions = new HashMap<String, String>();
        serverOptions.put("jboss.sasl.local-user.default-user", "$local");
        SaslServer server = Sasl.createSaslServer(LOCAL_USER, "TestProtocol", "TestServer", serverOptions, serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", (char[]) null);
        Map<String, String> clientOptions = new HashMap<String, String>();
        clientOptions.put("jboss.sasl.local-user.quiet-auth", "true");        
        SaslClient client = Sasl.createSaslClient(new String[]{ LOCAL_USER }, null, "TestProtocol", "TestServer", clientOptions, clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] response = client.evaluateChallenge(new byte[0]);
        byte[] challenge = server.evaluateResponse(response);
        response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        assertNull(challenge);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("$local", server.getAuthorizationID());
    }    
    
    /**
     * Test an exchange where the client sends a bad response is correctly rejected.
     */

    @Test
    public void testBadExchange_CF() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", (char[]) null);
        SaslServer server = Sasl.createSaslServer(LOCAL_USER, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", (char[]) null);
        SaslClient client = Sasl.createSaslClient(new String[]{ LOCAL_USER }, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] response = client.evaluateChallenge(new byte[0]);
        byte[] challenge = server.evaluateResponse(response);
        response = client.evaluateChallenge(challenge);
        for (int i = 0; i < 8; i++) {
            response[i] = 0x00;
        }

        try {
            challenge = server.evaluateResponse(response);
            fail("Expected SaslException not thrown.");
        } catch (SaslException expected) {
        }

        assertFalse(server.isComplete());
     
        try {
            server.getAuthorizationID();
            fail("Expected IllegalStateException not thrown");
        } catch (IllegalStateException expected) {
        }
    }
    
    /**
     * Test an exchange where the client is passed the path to a file that does not exist.
     */

    @Test
    public void testBadFile_CF() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", (char[]) null);
        SaslServer server = Sasl.createSaslServer(LOCAL_USER, "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", (char[]) null);
        SaslClient client = Sasl.createSaslClient(new String[] { LOCAL_USER }, "George", "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] response = client.evaluateChallenge(new byte[0]);
        byte[] challenge = server.evaluateResponse(response);

        File nonExistant = new File("nonExistant.txt");
        String path = nonExistant.getAbsolutePath();
        challenge = new byte[Charsets.encodedLengthOf(path)];
        Charsets.encodeTo(path, challenge, 0);

        try {
            response = client.evaluateChallenge(challenge);
        } catch (SaslException expected) {
        }

        assertFalse(server.isComplete());

        try {
            server.getAuthorizationID();
            fail("Expected IllegalStateException not thrown");
        } catch (IllegalStateException expected) {
        }
    }    
    
    /**
     * Test an exchange where there is no authorization ID
     */

    @Test
    public void testNoAuthorizationId_CF() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", (char[]) null);
        SaslServer server = Sasl.createSaslServer(LOCAL_USER, "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", (char[]) null);
        SaslClient client = Sasl.createSaslClient(new String[] { LOCAL_USER }, null, "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] response = client.evaluateChallenge(new byte[0]);
        byte[] challenge = server.evaluateResponse(response);
        response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        assertNull(challenge);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }
    
    /*
     *  Normal SASL Client/Server interaction - Server First
     */

    /**
     * Test a successful exchange using the JBOSS-LOCAL-USER mechanism.
     */

    @Test
    public void testSuccessfulExchange_SF() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", (char[]) null);
        SaslServer server = Sasl.createSaslServer(LOCAL_USER, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", (char[]) null);
        SaslClient client = Sasl.createSaslClient(new String[]{ LOCAL_USER }, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        byte[] challenge = server.evaluateResponse(new byte[0]);
        byte[] response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        assertNull(challenge);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }
    
    /**
     * Test a successful exchange using the JBOSS-LOCAL-USER mechanism with quiet client side
     * and default user server side.
     */

    @Test
    public void testSuccessfulQuietExchange_SF() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("$local", (char[]) null);
        Map<String, String> serverOptions = new HashMap<String, String>();
        serverOptions.put("jboss.sasl.local-user.default-user", "$local");
        SaslServer server = Sasl.createSaslServer(LOCAL_USER, "TestProtocol", "TestServer", serverOptions, serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", (char[]) null);
        Map<String, String> clientOptions = new HashMap<String, String>();
        clientOptions.put("jboss.sasl.local-user.quiet-auth", "true");        
        SaslClient client = Sasl.createSaslClient(new String[]{ LOCAL_USER }, null, "TestProtocol", "TestServer", clientOptions, clientCallback);

        byte[] challenge = server.evaluateResponse(new byte[0]);
        byte[] response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        assertNull(challenge);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("$local", server.getAuthorizationID());
    }    
    
    /**
     * Test an exchange where the client sends a bad response is correctly rejected.
     */

    @Test
    public void testBadExchange_SF() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", (char[]) null);
        SaslServer server = Sasl.createSaslServer(LOCAL_USER, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", (char[]) null);
        SaslClient client = Sasl.createSaslClient(new String[]{ LOCAL_USER }, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        byte[] challenge = server.evaluateResponse(new byte[0]);
        byte[] response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        response = client.evaluateChallenge(challenge);
        for (int i = 0; i < 8; i++) {
            response[i] = 0x00;
        }

        try {
            challenge = server.evaluateResponse(response);
            fail("Expected SaslException not thrown.");
        } catch (SaslException expected) {
        }

        assertFalse(server.isComplete());
     
        try {
            server.getAuthorizationID();
            fail("Expected IllegalStateException not thrown");
        } catch (IllegalStateException expected) {
        }
    }
    
    /**
     * Test an exchange where the client is passed the path to a file that does not exist.
     */

    @Test
    public void testBadFile_SF() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", (char[]) null);
        SaslServer server = Sasl.createSaslServer(LOCAL_USER, "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", (char[]) null);
        SaslClient client = Sasl.createSaslClient(new String[] { LOCAL_USER }, "George", "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), clientCallback);

        byte[] challenge = server.evaluateResponse(new byte[0]);
        byte[] response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);

        File nonExistant = new File("nonExistant.txt");
        String path = nonExistant.getAbsolutePath();
        challenge = new byte[Charsets.encodedLengthOf(path)];
        Charsets.encodeTo(path, challenge, 0);

        try {
            response = client.evaluateChallenge(challenge);
        } catch (SaslException expected) {
        }

        assertFalse(server.isComplete());

        try {
            server.getAuthorizationID();
            fail("Expected IllegalStateException not thrown");
        } catch (IllegalStateException expected) {
        }
    }    
    
    /**
     * Test an exchange where there is no authorization ID
     */

    @Test
    public void testNoAuthorizationId_SF() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", (char[]) null);
        SaslServer server = Sasl.createSaslServer(LOCAL_USER, "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", (char[]) null);
        SaslClient client = Sasl.createSaslClient(new String[] { LOCAL_USER }, null, "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), clientCallback);

        byte[] challenge = server.evaluateResponse(new byte[0]);
        byte[] response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        assertNull(challenge);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }    

}
