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
package org.wildfly.security.sasl.external;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.junit.Ignore;
import org.junit.Test;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.util.AbstractSaslParticipant;

/**
 * Tests for the SASL Server for EXTERNAL mechanism (
 * <a href="https://tools.ietf.org/html/rfc4422#appendix-A">https://tools.ietf.org/html/rfc4422#appendix-A</a>).
 *
 * @author Josef Cacek
 */
public class ExternalSaslServerTest extends BaseTestCase {

    private static final String ADMIN = "admin";
    private static final String EXTERNAL = "EXTERNAL";

    private static final CallbackHandler CALLBACK_HANDLER_AUTHZ_ADMIN = callbacks -> {
        for (Callback callback : callbacks) {
            if (callback instanceof AuthorizeCallback) {
                final AuthorizeCallback ac = (AuthorizeCallback) callback;
                ac.setAuthorized(ADMIN.equals(ac.getAuthorizationID()));
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    };

    @Test
    @Ignore("ELY-799,ELY-788")
    public void testMechanismNames() throws Exception {
        SaslServerFactory factory = obtainSaslServerFactory(ExternalSaslServerFactory.class);
        assertNotNull("SaslServerFactory not registered", factory);

        final String[] empty = new String[] {};
        assertArrayEquals(empty, factory.getMechanismNames(setProps(Sasl.POLICY_FORWARD_SECRECY)));
        assertArrayEquals(empty, factory.getMechanismNames(setProps(Sasl.POLICY_NOACTIVE)));
        assertArrayEquals(empty, factory.getMechanismNames(setProps(Sasl.POLICY_NOANONYMOUS)));
        assertArrayEquals(empty, factory.getMechanismNames(setProps(Sasl.POLICY_NODICTIONARY)));
        assertArrayEquals(empty, factory.getMechanismNames(setProps(Sasl.POLICY_NOPLAINTEXT)));
        assertArrayEquals(empty, factory.getMechanismNames(setProps(Sasl.POLICY_PASS_CREDENTIALS)));

        final String[] allMechanisms = new String[] { EXTERNAL };
        assertArrayEquals(allMechanisms,
                factory.getMechanismNames(setProps(WildFlySasl.MECHANISM_QUERY_ALL, Sasl.POLICY_NOPLAINTEXT)));
        assertArrayEquals(allMechanisms, factory.getMechanismNames(null));
    }

    @Test
    @Ignore("ELY-800,ELY-788")
    public void testCreateSaslServerUsingRegistry() throws Exception {
        assertNull(Sasl.createSaslServer(EXTERNAL, "test", "localhost", setProps(Sasl.POLICY_FORWARD_SECRECY), null));
        assertNull(Sasl.createSaslServer(EXTERNAL, "test", "localhost", setProps(Sasl.POLICY_NOACTIVE), null));
        assertNull(Sasl.createSaslServer(EXTERNAL, "test", "localhost", setProps(Sasl.POLICY_NOANONYMOUS), null));
        assertNull(Sasl.createSaslServer(EXTERNAL, "test", "localhost", setProps(Sasl.POLICY_NODICTIONARY), null));
        assertNull(Sasl.createSaslServer(EXTERNAL, "test", "localhost", setProps(Sasl.POLICY_NOPLAINTEXT), null));
        assertNull(Sasl.createSaslServer(EXTERNAL, "test", "localhost", setProps(Sasl.POLICY_PASS_CREDENTIALS), null));

        SaslServer server = Sasl.createSaslServer(EXTERNAL, "test", "localhost", null, null);
        assertNotNull(server);
        assertEquals(ExternalSaslServer.class, server.getClass());
    }

    @Test
    @Ignore("ELY-800,ELY-788")
    public void testCreateSaslServerUsingFactory() throws Exception {
        SaslServerFactory factory = obtainSaslServerFactory(ExternalSaslServerFactory.class);
        assertNotNull("SaslServerFactory not registered", factory);

        assertNull(factory.createSaslServer(EXTERNAL, "test", "localhost", setProps(Sasl.POLICY_FORWARD_SECRECY), null));
        assertNull(factory.createSaslServer(EXTERNAL, "test", "localhost", setProps(Sasl.POLICY_NOACTIVE), null));
        assertNull(factory.createSaslServer(EXTERNAL, "test", "localhost", setProps(Sasl.POLICY_NOANONYMOUS), null));
        assertNull(factory.createSaslServer(EXTERNAL, "test", "localhost", setProps(Sasl.POLICY_NODICTIONARY), null));
        assertNull(factory.createSaslServer(EXTERNAL, "test", "localhost", setProps(Sasl.POLICY_NOPLAINTEXT), null));
        assertNull(factory.createSaslServer(EXTERNAL, "test", "localhost",
                setProps(Sasl.POLICY_NOPLAINTEXT, WildFlySasl.MECHANISM_QUERY_ALL), null));
        assertNull(factory.createSaslServer(EXTERNAL, "test", "localhost", setProps(Sasl.POLICY_PASS_CREDENTIALS), null));

        SaslServer server = factory.createSaslServer(EXTERNAL, "test", "localhost", null, null);
        assertNotNull(server);
        assertEquals(ExternalSaslServer.class, server.getClass());
    }

    @Test
    @Ignore("ELY-803")
    public void testAuthnClientData() throws Exception {
        SaslServerFactory factory = obtainSaslServerFactory(ExternalSaslServerFactory.class);
        assertNotNull("SaslServerFactory not registered", factory);

        SaslServer saslServer = factory.createSaslServer(EXTERNAL, "test", "localhost", setProps(),
                CALLBACK_HANDLER_AUTHZ_ADMIN);
        assertEquals(EXTERNAL, saslServer.getMechanismName());

        assertFalse(saslServer.isComplete());

        // The challenge is null if the authentication has succeeded and no more challenge data is to be sent to the client.
        assertNull(saslServer.evaluateResponse(ADMIN.getBytes(StandardCharsets.UTF_8)));

        assertTrue(saslServer.isComplete());
        assertEquals(ADMIN, saslServer.getAuthorizationID());


        try {
            saslServer.evaluateResponse(AbstractSaslParticipant.NO_BYTES);
            fail("evaluateResponse() invocation should fail  when the authentication is already completed");
        } catch (SaslException e) {
            // expected
        }
    }

    /**
     * Test failing (as we only authenticate "admin") authn for unsupported data "test" from client.
     */
    @Test(expected = SaslException.class)
    public void testFailedAuthn() throws Exception {
        SaslServer saslServer = obtainSaslServerFactory(ExternalSaslServerFactory.class).createSaslServer(EXTERNAL, "test",
                "localhost", setProps(), CALLBACK_HANDLER_AUTHZ_ADMIN);
        assertFalse(saslServer.isComplete());
        saslServer.evaluateResponse("test".getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Test failing authn (as we only authenticate "admin") for empty data received from client.
     */
    @Test(expected = SaslException.class)
    public void testAuthnEmptyData() throws Exception {
        SaslServer saslServer = obtainSaslServerFactory(ExternalSaslServerFactory.class).createSaslServer(EXTERNAL, "test",
                "localhost", setProps(), CALLBACK_HANDLER_AUTHZ_ADMIN);

        assertFalse(saslServer.isComplete());

        saslServer.evaluateResponse(AbstractSaslParticipant.NO_BYTES);
    }

    @Test
    @Ignore("ELY-802")
    public void testWrapUnwrap() throws Exception {
        SaslServerFactory factory = obtainSaslServerFactory(ExternalSaslServerFactory.class);
        assertNotNull("SaslServerFactory not registered", factory);

        SaslServer saslServer = factory.createSaslServer(EXTERNAL, "test", "localhost", setProps(),
                CALLBACK_HANDLER_AUTHZ_ADMIN);

        try {
            saslServer.wrap(new byte[] {}, 0, 0);
            fail("wrap() invocation should throw IllegalStateException as not yet completed");
        } catch (IllegalStateException e) {
            // expected
        }
        try {
            saslServer.unwrap(new byte[] {}, 0, 0);
            fail("unwrap() invocation should throw IllegalStateException as not yet completed");
        } catch (IllegalStateException e) {
            // expected
        }

        saslServer.evaluateResponse(ADMIN.getBytes(StandardCharsets.UTF_8));
        assertTrue(saslServer.isComplete());

        try {
            saslServer.wrap(new byte[] {}, 0, 0);
            fail("wrap() invocation should throw IllegalStateException as this mechanism supports neither integrity nor privacy");
        } catch (IllegalStateException e) {
            // expected
        }
        try {
            saslServer.unwrap(new byte[] {}, 0, 0);
            fail("wrap() invocation should throw IllegalStateException as this mechanism supports neither integrity nor privacy");
        } catch (IllegalStateException e) {
            // expected
        }
    }

    private Map<String, ?> setProps(String... propNames) {
        return Stream.of(propNames).collect(Collectors.toMap(Function.identity(), s -> "true"));
    }
}
