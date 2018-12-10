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

package org.wildfly.security.sasl.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.junit.Test;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.localuser.LocalUserServerFactory;

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
        SaslServer server = new SaslServerBuilder(LocalUserServerFactory.class, LOCAL_USER)
                .setUserName("George")
                .build();

        CallbackHandler clientCallback = createClientCallbackHandler("George");
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

        server.dispose();
    }

    /**
     * Test a successful exchange using the JBOSS-LOCAL-USER mechanism with quiet client side
     * and default user server side.
     */

    @Test
    public void testSuccessfulQuietExchange_CF() throws Exception {
        Map<String, Object> serverOptions = new HashMap<>();
        serverOptions.put("wildfly.sasl.local-user.default-user", "$local");
        final Map<String, String> passwordMap = new HashMap<String, String>();
        passwordMap.put("$local", null);
        passwordMap.put("George", null);
        SaslServer server = new SaslServerBuilder(LocalUserServerFactory.class, LOCAL_USER)
                .setPasswordMap(passwordMap)
                .setProperties(serverOptions)
                .build();


        CallbackHandler clientCallback = createClientCallbackHandler("George");
        Map<String, String> clientOptions = new HashMap<String, String>();
        clientOptions.put("wildfly.sasl.local-user.quiet-auth", "true");
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

        server.dispose();
    }

    /**
     * Test an exchange where the client sends a bad response is correctly rejected.
     */

    @Test
    public void testBadExchange_CF() throws Exception {
        SaslServer server = new SaslServerBuilder(LocalUserServerFactory.class, LOCAL_USER)
                .setUserName("George")
                .build();


        CallbackHandler clientCallback = createClientCallbackHandler("George");
        SaslClient client = Sasl.createSaslClient(new String[]{LOCAL_USER}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

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

        server.dispose();
    }

    /**
     * Test an exchange where the client is passed the path to a file that does not exist.
     */

    @Test
    public void testBadFile_CF() throws Exception {
        SaslServer server = new SaslServerBuilder(LocalUserServerFactory.class, LOCAL_USER)
                .setUserName("George")
                .build();

        CallbackHandler clientCallback = createClientCallbackHandler("George");
        SaslClient client = Sasl.createSaslClient(new String[]{LOCAL_USER}, "George", "TestProtocol", "TestServer",
                Collections.<String, Object>emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] response = client.evaluateChallenge(new byte[0]);
        byte[] challenge = server.evaluateResponse(response);

        File nonExistant = new File("nonExistant.txt");
        String path = nonExistant.getAbsolutePath();
        challenge = CodePointIterator.ofString(path).asUtf8(true).drain();

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

        server.dispose();
    }

    /**
     * Test an exchange where there is no authorization ID
     */

    @Test
    public void testNoAuthorizationId_CF() throws Exception {
        SaslServer server = new SaslServerBuilder(LocalUserServerFactory.class, LOCAL_USER)
                .setUserName("George")
                .build();

        CallbackHandler clientCallback = createClientCallbackHandler("George");
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

        server.dispose();
    }

    /*
     *  Normal SASL Client/Server interaction - Server First
     */

    /**
     * Test a successful exchange using the JBOSS-LOCAL-USER mechanism.
     */

    @Test
    public void testSuccessfulExchange_SF() throws Exception {
        SaslServer server = new SaslServerBuilder(LocalUserServerFactory.class, LOCAL_USER)
                .setUserName("George")
                .build();

        CallbackHandler clientCallback = createClientCallbackHandler("George");
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

        server.dispose();
    }

    /**
     * Test a successful exchange using the JBOSS-LOCAL-USER mechanism with quiet client side
     * and default user server side.
     */

    @Test
    public void testSuccessfulQuietExchange_SF() throws Exception {
        Map<String, Object> serverOptions = new HashMap<>();
        serverOptions.put("wildfly.sasl.local-user.default-user", "$local");
        SaslServer server = new SaslServerBuilder(LocalUserServerFactory.class, LOCAL_USER)
                .setUserName("$local")
                .setProperties(serverOptions)
                .build();

        CallbackHandler clientCallback = createClientCallbackHandler("George");
        Map<String, String> clientOptions = new HashMap<String, String>();
        clientOptions.put("wildfly.sasl.local-user.quiet-auth", "true");
        SaslClient client = Sasl.createSaslClient(new String[]{LOCAL_USER}, null, "TestProtocol", "TestServer", clientOptions, clientCallback);

        byte[] challenge = server.evaluateResponse(new byte[0]);
        byte[] response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        assertNull(challenge);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("$local", server.getAuthorizationID());

        server.dispose();
    }

    /**
     * Test an exchange where the client sends a bad response is correctly rejected.
     */

    @Test
    public void testBadExchange_SF() throws Exception {
        SaslServer server = new SaslServerBuilder(LocalUserServerFactory.class, LOCAL_USER)
                .setUserName("George")
                .build();

        CallbackHandler clientCallback = createClientCallbackHandler("George");
        SaslClient client = Sasl.createSaslClient(new String[]{LOCAL_USER}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

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

        server.dispose();
    }

    /**
     * Test an exchange where the client is passed the path to a file that does not exist.
     */

    @Test
    public void testBadFile_SF() throws Exception {
        SaslServer server = new SaslServerBuilder(LocalUserServerFactory.class, LOCAL_USER)
                .setUserName("George")
                .build();

        CallbackHandler clientCallback = createClientCallbackHandler("George");
        SaslClient client = Sasl.createSaslClient(new String[]{LOCAL_USER}, "George", "TestProtocol", "TestServer",
                Collections.<String, Object>emptyMap(), clientCallback);

        byte[] challenge = server.evaluateResponse(new byte[0]);
        byte[] response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);

        File nonExistant = new File("nonExistant.txt");
        String path = nonExistant.getAbsolutePath();
        challenge = CodePointIterator.ofString(path).asUtf8(true).drain();

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

        server.dispose();
    }

    /**
     * Test an exchange where there is no authorization ID
     */

    @Test
    public void testNoAuthorizationId_SF() throws Exception {
        SaslServer server = new SaslServerBuilder(LocalUserServerFactory.class, LOCAL_USER)
                .setUserName("George")
                .build();

        CallbackHandler clientCallback = createClientCallbackHandler("George");
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

        server.dispose();
    }

    /**
     * Test that is a SaslServer is disposed of before the challenge is verified the temporary file is deleted.
     */

    @Test
    public void testTmpFileDeleted_SF() throws Exception {
        SaslServer server = new SaslServerBuilder(LocalUserServerFactory.class, LOCAL_USER)
                .setUserName("George")
                .build();

        byte[] challenge = server.evaluateResponse(new byte[0]);
        challenge = server.evaluateResponse(new byte[]{0}); // Simulate initial message from client.
        final String path = new String(challenge, StandardCharsets.UTF_8);
        final File file = new File(path);

        assertTrue("Temporary file was created.", file.exists());
        server.dispose();
        assertFalse("Temporary file was deleted.", file.exists());
    }

    /**
     * Test a successful exchange with minimal callback handler.
     */
    @Test
    public void testMinimalCallbackHandler() throws Exception {
        SaslServer server = new SaslServerBuilder(LocalUserServerFactory.class, LOCAL_USER)
                .setUserName("George")
                .build();

        CallbackHandler clientCallback = callbacks -> {
            throw new UnsupportedCallbackException(null);
        };
        SaslClient client = Sasl.createSaslClient(new String[]{ LOCAL_USER }, "George", "TestProtocol", "TestServer", Collections.emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] response = client.evaluateChallenge(new byte[0]);
        byte[] challenge = server.evaluateResponse(response);
        response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        assertNull(challenge);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("George", server.getAuthorizationID());

        server.dispose();
    }


    private CallbackHandler createClientCallbackHandler(final String expectedUsername) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.empty()
                                .useName(expectedUsername)
                                .useRealm("mainRealm")
                                .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism(LOCAL_USER)));


        return ClientUtils.getCallbackHandler(new URI("doesnot://matter?"), context);
    }
}
