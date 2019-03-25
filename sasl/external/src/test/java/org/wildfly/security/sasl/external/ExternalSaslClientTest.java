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
import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.test.BaseTestCase;

/**
 * Tests for the SASL Client for EXTERNAL mechanism (
 * <a href="https://tools.ietf.org/html/rfc4422#appendix-A">https://tools.ietf.org/html/rfc4422#appendix-A</a>).
 *
 * @author Josef Cacek
 */
public class ExternalSaslClientTest extends BaseTestCase {

    private static final byte[] BYTES_EMPTY = new byte[0];
    private static final String ADMIN = "admin";
    private static final String EXTERNAL = "EXTERNAL";

    private static final String[] MECHANISMS_EXTERNAL_ONLY = new String[] { EXTERNAL };
    private static final String[] MECHANISMS_WITH_EXTERNAL = new String[] { EXTERNAL, "TEST" };
    private static final String[] MECHANISMS_WITHOUT_EXTERNAL = new String[] { "TEST" };
    private static final Provider provider = WildFlyElytronSaslExternalProvider.getInstance();

    @BeforeClass
    public static void registerProvider() {
        Security.insertProviderAt(provider, 1);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testMechanismNames() throws Exception {
        SaslClientFactory factory = obtainSaslClientFactory(ExternalSaslClientFactory.class);
        assertNotNull("SaslServerFactory not registered", factory);

        final String[] empty = new String[] {};
        assertArrayEquals(empty, factory.getMechanismNames(setProps(Sasl.POLICY_FORWARD_SECRECY)));
        assertArrayEquals(MECHANISMS_EXTERNAL_ONLY, factory.getMechanismNames(setProps(Sasl.POLICY_NOACTIVE)));
        assertArrayEquals(empty, factory.getMechanismNames(setProps(Sasl.POLICY_NOANONYMOUS)));
        assertArrayEquals(MECHANISMS_EXTERNAL_ONLY, factory.getMechanismNames(setProps(Sasl.POLICY_NODICTIONARY)));
        assertArrayEquals(MECHANISMS_EXTERNAL_ONLY, factory.getMechanismNames(setProps(Sasl.POLICY_NOPLAINTEXT)));
        assertArrayEquals(empty, factory.getMechanismNames(setProps(Sasl.POLICY_PASS_CREDENTIALS)));

        assertArrayEquals(MECHANISMS_EXTERNAL_ONLY,
                factory.getMechanismNames(setProps(WildFlySasl.MECHANISM_QUERY_ALL, Sasl.POLICY_NOPLAINTEXT)));
        assertArrayEquals(MECHANISMS_EXTERNAL_ONLY, factory.getMechanismNames(null));
    }

    @Test
    public void testCreateSaslClientUsingRegistry() throws Exception {
        assertNull(Sasl.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost",
                setProps(Sasl.POLICY_FORWARD_SECRECY), null));
        assertNull(Sasl.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost",
                setProps(Sasl.POLICY_NOANONYMOUS), null));
        assertNull(Sasl.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost",
                setProps(Sasl.POLICY_PASS_CREDENTIALS), null));


        SaslClient saslClient = Sasl.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost", setProps(),
                null);
        assertNotNull(saslClient);
        assertEquals(ExternalSaslClient.class, saslClient.getClass());

        saslClient = Sasl.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost", setProps(),
                null);
        assertNotNull(saslClient);
        assertEquals(ExternalSaslClient.class, saslClient.getClass());

        assertNull(Sasl.createSaslClient(MECHANISMS_WITHOUT_EXTERNAL, null, "test", "localhost", setProps(), null));
        assertNotNull(Sasl.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost", null, null));
    }

    @Test
    public void testCreateSaslClientUsingFactory() throws Exception {
        final SaslClientFactory factory = obtainSaslClientFactory(ExternalSaslClientFactory.class);
        assertNotNull("SaslClientFactory not registered", factory);

        assertNull(factory.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost",
                setProps(Sasl.POLICY_FORWARD_SECRECY), null));
        assertNull(factory.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost",
                setProps(Sasl.POLICY_NOANONYMOUS), null));
        assertNull(factory.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost",
                setProps(Sasl.POLICY_PASS_CREDENTIALS), null));

        final SaslClient saslClient = factory.createSaslClient(MECHANISMS_WITH_EXTERNAL, null, "test", "localhost", setProps(),
                null);
        assertNotNull(saslClient);
        assertEquals(ExternalSaslClient.class, saslClient.getClass());

        assertNotNull(factory.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost", null, null));
    }

    @Test
    public void testDontUseQueryAllPolicyInCreateMethod() throws Exception {
        final SaslClientFactory factory = obtainSaslClientFactory(ExternalSaslClientFactory.class);
        assertNotNull("SaslClientFactory not registered", factory);

        assertNull(factory.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost",
                setProps(Sasl.POLICY_PASS_CREDENTIALS, WildFlySasl.MECHANISM_QUERY_ALL), null));
    }

    @Test
    public void testCreateSaslClientWithValidFiltering() throws Exception {
        assertNotNull(Sasl.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost", setProps(Sasl.POLICY_NOACTIVE),
                null));
        assertNotNull(Sasl.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost",
                setProps(Sasl.POLICY_NODICTIONARY), null));
        assertNotNull(Sasl.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost",
                setProps(Sasl.POLICY_NOPLAINTEXT), null));

        final SaslClientFactory factory = obtainSaslClientFactory(ExternalSaslClientFactory.class);
        assertNotNull("SaslClientFactory not registered", factory);

        assertNotNull(factory.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost",
                setProps(Sasl.POLICY_NOACTIVE), null));
        assertNotNull(factory.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost",
                setProps(Sasl.POLICY_NODICTIONARY), null));
        assertNotNull(factory.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost",
                setProps(Sasl.POLICY_NOPLAINTEXT), null));
    }

    @Test
    public void testServerChallengeProvideAuthzId() throws Exception {
        final SaslClientFactory factory = obtainSaslClientFactory(ExternalSaslClientFactory.class);

        final SaslClient saslClient = factory.createSaslClient(MECHANISMS_EXTERNAL_ONLY, ADMIN, "test", "localhost", setProps(),
                null);

        assertEquals(EXTERNAL, saslClient.getMechanismName());
        assertTrue(saslClient.hasInitialResponse());
        assertFalse(saslClient.isComplete());

        // The challenge is null if the authentication has succeeded and no more challenge data is to be sent to the client.
        assertArrayEquals(ADMIN.getBytes(StandardCharsets.UTF_8), saslClient.evaluateChallenge(BYTES_EMPTY));

        assertTrue(saslClient.isComplete());

        try {
            saslClient.evaluateChallenge(BYTES_EMPTY);
            fail("evaluateChallenge() invocation should fail  when the authentication is already completed");
        } catch (SaslException e) {
            // expected
        }
    }

    @Test
    public void testServerChallengeEmptyAuthzId() throws Exception {
        final SaslClientFactory factory = obtainSaslClientFactory(ExternalSaslClientFactory.class);

        final SaslClient saslClient = factory.createSaslClient(MECHANISMS_EXTERNAL_ONLY, null, "test", "localhost", setProps(),
                null);

        assertEquals(EXTERNAL, saslClient.getMechanismName());
        assertTrue(saslClient.hasInitialResponse());
        assertFalse(saslClient.isComplete());

        // The challenge is null if the authentication has succeeded and no more challenge data is to be sent to the client.
        assertArrayEquals(BYTES_EMPTY, saslClient.evaluateChallenge(BYTES_EMPTY));

        assertTrue(saslClient.isComplete());

        try {
            saslClient.evaluateChallenge(BYTES_EMPTY);
            fail("evaluateChallenge() invocation should fail  when the authentication is already completed");
        } catch (SaslException e) {
            // expected
        }
    }

    /**
     * Test failing (as we only authenticate "admin") authn for unsupported data "test" from client.
     */
    @Test(expected = SaslException.class)
    public void testWrongServerChallenge() throws Exception {
        final SaslClientFactory factory = obtainSaslClientFactory(ExternalSaslClientFactory.class);
        final SaslClient saslClient = factory.createSaslClient(MECHANISMS_EXTERNAL_ONLY, ADMIN, "test", "localhost", setProps(),
                null);
        assertFalse(saslClient.isComplete());
        saslClient.evaluateChallenge("test".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void testWrapUnwrap() throws Exception {
        final SaslClientFactory factory = obtainSaslClientFactory(ExternalSaslClientFactory.class);

        final SaslClient saslClient = factory.createSaslClient(MECHANISMS_EXTERNAL_ONLY, ADMIN, "test", "localhost", setProps(),
                null);

        try {
            saslClient.wrap(new byte[] {}, 0, 0);
            fail("wrap() invocation should throw IllegalStateException as not yet completed");
        } catch (IllegalStateException e) {
            // expected
        }
        try {
            saslClient.unwrap(new byte[] {}, 0, 0);
            fail("unwrap() invocation should throw IllegalStateException as not yet completed");
        } catch (IllegalStateException e) {
            // expected
        }

        saslClient.evaluateChallenge(BYTES_EMPTY);
        assertTrue(saslClient.isComplete());

        try {
            saslClient.wrap(new byte[] {}, 0, 0);
            fail("wrap() invocation should throw IllegalStateException as this mechanism supports neither integrity nor privacy");
        } catch (IllegalStateException e) {
            // expected
        }
        try {
            saslClient.unwrap(new byte[] {}, 0, 0);
            fail("wrap() invocation should throw IllegalStateException as this mechanism supports neither integrity nor privacy");
        } catch (IllegalStateException e) {
            // expected
        }
    }

    private Map<String, ?> setProps(String... propNames) {
        return Stream.of(propNames).collect(Collectors.toMap(Function.identity(), s -> "true"));
    }
}
