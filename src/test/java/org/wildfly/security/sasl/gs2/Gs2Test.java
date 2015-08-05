/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.gs2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.wildfly.security.sasl.gs2.Gs2.GS2_KRB5;
import static org.wildfly.security.sasl.gs2.Gs2.GS2_KRB5_PLUS;
import static org.wildfly.security.sasl.gs2.Gs2.OID_KRB5;
import static org.wildfly.security.sasl.gs2.Gs2.OID_SPNEGO;
import static org.wildfly.security.sasl.gs2.Gs2.SPNEGO;
import static org.wildfly.security.sasl.gs2.Gs2.SPNEGO_PLUS;
import static org.wildfly.security.sasl.gssapi.JaasUtil.loginClient;
import static org.wildfly.security.sasl.gssapi.JaasUtil.loginServer;

import java.io.IOException;
import java.net.URI;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.gssapi.TestKDC;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.sasl.util.ChannelBindingSaslClientFactory;
import org.wildfly.security.sasl.util.PropertiesSaslClientFactory;
import org.wildfly.security.sasl.util.ProtocolSaslClientFactory;
import org.wildfly.security.sasl.util.ServerNameSaslClientFactory;

/**
 * Client and server side tests for the GS2 SASL mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class Gs2Test extends BaseTestCase {

    private static final String TEST_SERVER_1 = "test_server_1";
    private static TestKDC testKdc;
    private static Subject clientSubject;
    private static Subject serverSubject;
    private SaslServer saslServer;
    private SaslClient saslClient;

    @BeforeClass
    public static void init() throws LoginException {
        testKdc = new TestKDC();
        testKdc.startDirectoryService();
        testKdc.startKDC();
        clientSubject = loginClient();
        serverSubject = loginServer();
    }

    @AfterClass
    public static void stop() {
        if (testKdc != null) {
            testKdc.stopAll();
            testKdc = null;
        }
        clientSubject = null;
        serverSubject = null;
    }

    @After
    public void dispose() throws Exception {
        if(saslClient != null) saslClient.dispose();
        if(saslServer != null) saslServer.dispose();
    }

    @Test
    public void testChannelBindingIndirect_Server() throws Exception {
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties are set, an appropriate Gs2SaslServer should be returned
        saslServer = getIndirectSaslServer(GS2_KRB5, "sasl", TEST_SERVER_1, props, null, null);
        assertEquals(GS2_KRB5, saslServer.getMechanismName());

        // Require channel binding
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, Boolean.toString(true));
        saslServer = getIndirectSaslServer(GS2_KRB5_PLUS, "sasl", TEST_SERVER_1, props, "tls-unique", new byte[0]);
        assertEquals(GS2_KRB5_PLUS, saslServer.getMechanismName());

        // If channel binding is required even though a non-PLUS mechanism is specified, no server should be returned
        saslServer = getIndirectSaslServer(GS2_KRB5, "sasl", TEST_SERVER_1, props, null, null);
        assertNull(saslServer);
    }

    @Test
    public void testChannelBindingDirect_Server() {
        SaslServerFactory factory = obtainSaslServerFactory(Gs2SaslServerFactory.class);
        assertNotNull("SaslServerFactory not registered", factory);

        String[] mechanisms;
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties set
        mechanisms = factory.getMechanismNames(props);
        assertMechanisms(new String[]{GS2_KRB5, GS2_KRB5_PLUS}, mechanisms);

        // Require channel binding
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, Boolean.toString(true));
        mechanisms = factory.getMechanismNames(props);
        assertMechanisms(new String[]{GS2_KRB5_PLUS}, mechanisms);
    }

    @Test
    public void testChannelBindingIndirect_Client() throws Exception {
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties are set, an appropriate Gs2SaslClient should be returned
        saslClient = getIndirectSaslClient(new String[]{GS2_KRB5}, null, "sasl", TEST_SERVER_1, props, null, null);
        assertEquals(Gs2SaslClient.class, saslClient.getClass());
        assertEquals(GS2_KRB5, saslClient.getMechanismName());

        // If channel binding is required even though only non-PLUS mechanisms are specified, no client should be returned
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, Boolean.toString(true));
        saslClient = getIndirectSaslClient(new String[]{"GS2-DT4PIK22T6A", GS2_KRB5}, null, "sasl", TEST_SERVER_1, props, null, null);
        assertNull(saslClient);

        // If channel binding is required, an appropriate Gs2SaslClient should be returned
        saslClient = getIndirectSaslClient(new String[]{"GS2-DT4PIK22T6A-PLUS", GS2_KRB5_PLUS}, null, "sasl", TEST_SERVER_1, props, "tls-unique", new byte[0]);
        assertEquals(Gs2SaslClient.class, saslClient.getClass());
        assertEquals(GS2_KRB5_PLUS, saslClient.getMechanismName());
    }

    @Test
    public void testChannelBindingDirect_Client() {
        SaslClientFactory factory = obtainSaslClientFactory(Gs2SaslClientFactory.class);
        assertNotNull("SaslClientFactory not registered", factory);

        String[] mechanisms;
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties set
        mechanisms = factory.getMechanismNames(props);
        assertMechanisms(new String[]{ GS2_KRB5, GS2_KRB5_PLUS }, mechanisms);

        // Request channel binding
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, Boolean.toString(true));
        mechanisms = factory.getMechanismNames(props);
        assertMechanisms(new String[]{GS2_KRB5_PLUS}, mechanisms);
    }

    // -- Successful authentication exchanges --

    @Test
    public void testKrb5AuthenticationWithoutChannelBinding() throws Exception {
        saslServer = getSaslServer(GS2_KRB5, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), null, null);
        assertNotNull(saslServer);
        assertEquals(GS2_KRB5, saslServer.getMechanismName());
        assertFalse(saslServer.isComplete());

        saslClient = getSaslClient(new String[] { GS2_KRB5 }, null, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), null, null);
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof Gs2SaslClient);
        assertTrue(saslClient.hasInitialResponse());
        assertFalse(saslClient.isComplete());

        byte[] message = evaluateChallenge(new byte[0]);
        assertFalse(saslClient.isComplete());
        assertFalse(saslServer.isComplete());

        message = evaluateResponse(message);
        assertTrue(saslServer.isComplete());
        assertNotNull(message);
        assertFalse(saslClient.isComplete());

        message = evaluateChallenge(message);
        assertTrue(saslClient.isComplete());
        assertNull(message);

        assertEquals("jduke@WILDFLY.ORG", saslServer.getAuthorizationID());
    }

    @Test
    public void testKrb5AuthenticationWithChannelBinding() throws Exception {
        Map<String, Object> props = new HashMap<String, Object>();
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, Boolean.toString(true));
        saslServer = getSaslServer(GS2_KRB5_PLUS, "sasl", TEST_SERVER_1, props, "tls-unique", new byte[0]);
        assertNotNull(saslServer);
        assertEquals(GS2_KRB5_PLUS, saslServer.getMechanismName());
        assertFalse(saslServer.isComplete());

        saslClient = getSaslClient(new String[]{GS2_KRB5_PLUS}, "jduke@WILDFLY.ORG", "sasl", TEST_SERVER_1, props, "tls-unique", new byte[0]);
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof Gs2SaslClient);
        assertTrue(saslClient.hasInitialResponse());
        assertFalse(saslClient.isComplete());

        byte[] message = evaluateChallenge(new byte[0]);
        assertFalse(saslClient.isComplete());
        assertFalse(saslServer.isComplete());

        message = evaluateResponse(message);
        assertTrue(saslServer.isComplete());
        assertNotNull(message);
        assertFalse(saslClient.isComplete());

        message = evaluateChallenge(message);
        assertTrue(saslClient.isComplete());
        assertNull(message);

        assertEquals("jduke@WILDFLY.ORG", saslServer.getAuthorizationID());
    }

    @Test
    public void testKrb5AuthenticationWithCredentialPassedIn() throws Exception {
        saslServer = getSaslServer(GS2_KRB5, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), null, null);
        assertNotNull(saslServer);
        assertEquals(GS2_KRB5, saslServer.getMechanismName());
        assertFalse(saslServer.isComplete());

        saslClient = getSaslClient(new String[] { GS2_KRB5 }, "jduke@WILDFLY.ORG", "sasl", TEST_SERVER_1, Collections.emptyMap(), null, null, true);
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof Gs2SaslClient);
        assertTrue(saslClient.hasInitialResponse());
        assertFalse(saslClient.isComplete());

        byte[] message = saslClient.evaluateChallenge(new byte[0]);
        assertFalse(saslClient.isComplete());
        assertFalse(saslServer.isComplete());

        message = saslServer.evaluateResponse(message);
        assertTrue(saslServer.isComplete());
        assertNotNull(message);
        assertFalse(saslClient.isComplete());

        message = saslClient.evaluateChallenge(message);
        assertTrue(saslClient.isComplete());
        assertNull(message);

        assertEquals("jduke@WILDFLY.ORG", saslServer.getAuthorizationID());
    }

    // -- Unsuccessful authentication exchanges --

    @Test
    public void testChannelBindingNotUsedByClientSupportedByServer() throws Exception {
        // gs2-cb-flag = "y"
        saslClient = getSaslClient(new String[] { GS2_KRB5 }, null, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(),
                "tls-unique", new byte[0]);
        assertNotNull(saslClient);

        saslServer = getSaslServer(GS2_KRB5_PLUS, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), "tls-unique", new byte[0]);
        assertNotNull(saslServer);

        byte[] message = evaluateChallenge(new byte[0]);
        try {
            message = evaluateResponse(message);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testChannelBindingUsedByClientUnsupportedByServer() throws Exception {
        // gs2-cb-flag = "p"
        Map<String, Object> props = new HashMap<String, Object>();
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, Boolean.toString(true));
        saslClient = getSaslClient(new String[] { GS2_KRB5_PLUS }, null, "sasl", TEST_SERVER_1, props, "tls-unique", new byte[0]);
        assertNotNull(saslClient);

        saslServer = getSaslServer(GS2_KRB5, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), null, null);
        assertNotNull(saslServer);

        byte[] message = evaluateChallenge(new byte[0]);
        try {
            message = evaluateResponse(message);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testChannelBindingUnsupportedByClientSupportedByServer() throws Exception {
        // gs2-cb-flag = "n"
        saslClient = getSaslClient(new String[] { GS2_KRB5 }, null, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), null, null);
        assertNotNull(saslClient);

        saslServer = getSaslServer(GS2_KRB5_PLUS, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), "tls-unique", new byte[0]);
        assertNotNull(saslServer);

        byte[] message = evaluateChallenge(new byte[0]);
        try {
            message = evaluateResponse(message);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testChannelBindingTypeMismatch() throws Exception {
        Map<String, Object> props = new HashMap<String, Object>();
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, Boolean.toString(true));
        saslClient = getSaslClient(new String[]{GS2_KRB5_PLUS}, null, "sasl", TEST_SERVER_1, props, "tls-unique", new byte[0]);
        assertNotNull(saslClient);

        saslServer = getSaslServer(GS2_KRB5_PLUS, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), "tls-unique-for-telnet", new byte[0]);
        assertNotNull(saslServer);

        byte[] message = evaluateChallenge(new byte[0]);
        try {
            message = evaluateResponse(message);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testChannelBindingDataMismatch() throws Exception {
        Map<String, Object> props = new HashMap<String, Object>();
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, Boolean.toString(true));
        saslClient = getSaslClient(new String[]{GS2_KRB5_PLUS}, null, "sasl", TEST_SERVER_1, props, "tls-unique", new byte[0]);
        assertNotNull(saslClient);

        saslServer = getSaslServer(GS2_KRB5_PLUS, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), "tls-unique", new byte[1]);
        assertNotNull(saslServer);

        byte[] message = evaluateChallenge(new byte[0]);
        try {
            message = evaluateResponse(message);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testUnauthorizedAuthorizationId() throws Exception {
        saslServer = getSaslServer(GS2_KRB5, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), null, null);
        assertNotNull(saslServer);

        saslClient = getSaslClient(new String[]{GS2_KRB5}, "bsmith@WILDFLY.ORG", "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), null, null);
        assertNotNull(saslClient);

        byte[] message = evaluateChallenge(new byte[0]);
        try {
            message = evaluateResponse(message);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testUnneededNonStdFlag() throws Exception {
        saslServer = getSaslServer(GS2_KRB5, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), null, null);
        assertNotNull(saslServer);

        saslClient = getSaslClient(new String[] { GS2_KRB5 }, null, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), null, null);
        assertNotNull(saslClient);

        byte[] origMessage = evaluateChallenge(new byte[0]);
        assertFalse(saslClient.isComplete());
        assertFalse(saslServer.isComplete());
        byte[] message = new byte[origMessage.length + 2];
        System.arraycopy(origMessage, 0, message, 2, origMessage.length);
        message[0] = (byte)'F'; // Insert gs2-nonstd-flag
        message[1] = (byte)',';

        try {
            message = evaluateResponse(message);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testInvalidGs2Header() throws Exception {
        saslServer = getSaslServer(GS2_KRB5, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), null, null);
        assertNotNull(saslServer);

        try {
            // gs2-header starts with an invalid character
            byte[] message = evaluateResponse(new byte[] {98, 44, 44, 1, 0, 110, -126, 1, -13, 48, -126, 1, -17, -96, 3, 2, 1, 5, -95, 3, 2, 1, 14, -94, 7, 3, 5, 0, 32, 0, 0, 0, -93, -126, 1, 11, 97, -126, 1, 7, 48, -126, 1, 3, -96, 3, 2, 1, 5, -95, 13, 27, 11, 87, 73, 76, 68, 70, 76, 89, 46, 79, 82, 71, -94, 32, 48, 30, -96, 3, 2, 1, 0, -95, 23, 48, 21, 27, 4, 115, 97, 115, 108, 27, 13, 116, 101, 115, 116, 95, 115, 101, 114, 118, 101, 114, 95, 49, -93, -127, -54, 48, -127, -57, -96, 3, 2, 1, 16, -94, -127, -65, 4, -127, -68, 85, 26, 77, -98, -85, 110, 17, -61, 12, -36, 34, -105, 37, 126, 2, 74, -98, 47, -23, -108, 57, 2, -4, 110, -71, -79, -99, 8, 71, 11, -90, -118, -23, -122, -115, 3, -105, 31, 52, -50, -104, 35, -7, -14, -102, -39, 110, 74, -17, 55, 78, 67, -52, 74, -59, 85, 40, 89, -8, -61, -109, -69, -126, 31, -100, 62, 37, 78, -20, 99, -24, -28, -54, 112, 34, 87, -4, 57, -46, 97, 118, 43, 103, -74, -39, -59, -16, -88, 8, -122, 81, 83, -103, 83, 49, 54, -20, -125, -110, 18, 26, 87, -22, -111, 71, 122, 110, 83, -33, -92, -94, 114, -92, -30, 114, 22, 46, 73, 38, 58, -117, -118, -23, -18, -91, -14, -42, 84, 37, -4, 90, 116, -77, -41, 93, 82, 54, -69, 114, 124, -82, -102, -50, -83, 17, 117, -86, 106, 50, 78, -122, 54, 57, -27, -89, -85, 125, -104, 110, -38, 75, -25, -85, 91, -77, -7, -68, 112, 87, -125, -28, 34, 71, -62, -34, -110, -122, -120, -86, -93, -41, 41, -34, 91, 88, -114, 112, 83, -92, -127, -54, 48, -127, -57, -96, 3, 2, 1, 16, -94, -127, -65, 4, -127, -68, -12, -3, 100, 43, -53, 16, 56, -68, 107, -81, 105, 26, 123, 115, 94, -94, 119, 36, 65, 109, 68, 26, -61, 22, -68, -68, 29, -36, -80, 80, -66, 24, 74, -7, -5, -43, 37, -75, 26, -33, 50, 89, 81, 125, 67, 64, 27, 104, 24, -42, 37, -19, 13, 65, 95, -25, -19, 23, 58, -42, -43, 88, -42, -1, 121, 87, -12, 17, 55, -116, 81, -107, -22, -56, 0, 99, -56, 56, 67, 57, -127, -3, 73, -56, -100, -74, -78, 27, 7, 58, -47, 23, -12, 20, 15, 65, -77, -36, 14, 122, -95, 45, -9, -116, 89, 87, 82, -117, -60, 22, 55, 104, 103, -71, -12, -45, -1, -44, 106, -117, 91, 83, -44, -60, 122, -100, -89, -65, 43, 107, -124, -57, -82, 113, 72, 77, -84, 121, -90, 57, -28, 90, 80, -33, 97, -62, 10, 124, 67, 97, 110, 87, 20, -78, -14, -9, 84, 64, 78, 28, -63, -78, -29, -93, 29, 111, -34, -128, 96, -53, -25, -84, -39, -44, 85, 96, 0, -35, 35, -100, -123, 7, -112, -26, -89, 14, 92, -28});
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testDisallowedMechanism() throws Exception {
        // SPNEGO must not be used as a GS2 mechanism (section 14.3 in RFC 5801)
        saslServer = getSaslServer(SPNEGO, "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), null, null);
        assertNull(saslServer);

        saslClient = getSaslClient(new String[] { SPNEGO, SPNEGO_PLUS }, "bsmith@WILDFLY.ORG", "sasl", TEST_SERVER_1, Collections.<String, Object>emptyMap(), null, null);
        assertNull(saslClient);
    }

    // -- Validate mapping SASL mechanism names to GSS-API OIDs and vice versa --

    @Test
    public void testGetSaslNameForMechanismOid() throws Exception {
        assertEquals(GS2_KRB5, Gs2.getSaslNameForMechanism(new Oid("1.2.840.113554.1.2.2"), false));
        assertEquals(SPNEGO_PLUS, Gs2.getSaslNameForMechanism(new Oid("1.3.6.1.5.5.2"), true));
        assertEquals("GS2-DT4PIK22T6A-PLUS", Gs2.getSaslNameForMechanism(new Oid("1.3.6.1.5.5.1.1"), true));
    }

    @Test
    public void testGetMechanismForSaslName() throws Exception {
        assertEquals(OID_KRB5, Gs2.getMechanismForSaslName(GSSManager.getInstance(), "GS2-KRB5-PLUS"));
        assertEquals(OID_SPNEGO, Gs2.getMechanismForSaslName(GSSManager.getInstance(), "SPNEGO"));
    }

    private SaslServer getIndirectSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, Object> props,
                                             final String bindingType, final byte[] bindingData) throws SaslException {
        try {
            return Subject.doAs(serverSubject, new PrivilegedExceptionAction<SaslServer>() {
                public SaslServer run() throws SaslException {
                    //TODO I don't like people having to pass in a callback handler to get this information
                    CallbackHandler cbh = new IndirectCallbackHandler(bindingType, bindingData);
                    return Sasl.createSaslServer(mechanism, protocol, serverName, props, cbh);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof SaslException) {
                throw (SaslException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }
    }

    private SaslServer getSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, Object> props,
                                     final String bindingType, final byte[] bindingData) throws SaslException {
        final SaslServerBuilder builder = new SaslServerBuilder(Gs2SaslServerFactory.class, mechanism)
                .setDontAssertBuiltServer();

        if (protocol != null) {
            builder.setProtocol(protocol);
        }
        if (serverName != null) {
            builder.setServerName(serverName);
        }
        if (props != null) {
            builder.setProperties(props);
        }
        if (bindingType != null || bindingData != null) {
            builder.setChannelBinding(bindingType, bindingData);
        }
        try {
            return Subject.doAs(serverSubject, new PrivilegedExceptionAction<SaslServer>() {
                public SaslServer run() throws Exception {
                    return builder.build();
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof SaslException) {
                throw (SaslException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }
    }

    private SaslClient getIndirectSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName,
                                             final Map<String, Object> props, final String bindingType, final byte[] bindingData) throws SaslException {
        try {
            return Subject.doAs(clientSubject, new PrivilegedExceptionAction<SaslClient>() {
                public SaslClient run() throws SaslException {
                    //TODO I don't like people having to pass in a callback handler to get this information
                    CallbackHandler cbh = new IndirectCallbackHandler(bindingType, bindingData);
                    return Sasl.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, cbh);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof SaslException) {
                throw (SaslException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }
    }

    private SaslClient getSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName,
            final Map<String, Object> props, final String bindingType, final byte[] bindingData) throws Exception {
        return getSaslClient(mechanisms, authorizationId, protocol, serverName, props, bindingType, bindingData, false);
    }

    private SaslClient getSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName,
                                     final Map<String, Object> props, final String bindingType,
                                     final byte[] bindingData, final boolean passCredential) throws Exception {
        GSSCredential credential = null;
        if (passCredential) {
            try {
                credential = Subject.doAs(clientSubject, new PrivilegedExceptionAction<GSSCredential>() {
                    public GSSCredential run() throws SaslException {
                        try {
                            return GSSManager.getInstance().createCredential(null, GSSCredential.INDEFINITE_LIFETIME, OID_KRB5, GSSCredential.INITIATE_ONLY);
                        } catch (GSSException e) {
                            throw new SaslException(e.getMessage());
                        }
                    }
                });
            } catch (PrivilegedActionException e) {
                if (e.getCause() instanceof SaslException) {
                    throw (SaslException) e.getCause();
                } else {
                    throw new RuntimeException(e.getCause());
                }
            }
        }
        final CallbackHandler cbh = createClientCallbackHandler(mechanisms, authorizationId, credential);
        SaslClientFactory clientFactory = obtainSaslClientFactory(Gs2SaslClientFactory.class);
        assertNotNull(clientFactory);
        if (bindingType != null || bindingData != null) {
            clientFactory = new ChannelBindingSaslClientFactory(clientFactory, bindingType, bindingData);
            assertNotNull(clientFactory);
        }
        if (protocol != null) {
            clientFactory = new ProtocolSaslClientFactory(clientFactory, protocol);
            assertNotNull(clientFactory);
        }
        if (serverName != null) {
            clientFactory = new ServerNameSaslClientFactory(clientFactory, serverName);
            assertNotNull(clientFactory);
        }
        if (props != null) {
            clientFactory = new PropertiesSaslClientFactory(clientFactory, props);
            assertNotNull(clientFactory);
        }

        final SaslClientFactory factory = clientFactory;
        try {
            return Subject.doAs(clientSubject, new PrivilegedExceptionAction<SaslClient>() {
                public SaslClient run() throws SaslException {
                    return factory.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, cbh);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof SaslException) {
                throw (SaslException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }
    }

    private CallbackHandler createClientCallbackHandler(final String[] mechanisms, final String authorizationId, final GSSCredential credential) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.EMPTY
                                .useAuthorizationName(authorizationId)
                                .useGSSCredential(credential)
                                .allowSaslMechanisms(mechanisms));

        return ClientUtils.getCallbackHandler(new URI("remote://localhost"), context);
    }

    private byte[] evaluateResponse(final byte[] response) throws SaslException {
        try {
            return Subject.doAs(serverSubject, new PrivilegedExceptionAction<byte[]>() {
                public byte[] run() throws SaslException {
                    return saslServer.evaluateResponse(response);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof SaslException) {
                throw (SaslException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }
    }

    private byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
        try {
            return Subject.doAs(clientSubject, new PrivilegedExceptionAction<byte[]>(){
                public byte[] run() throws SaslException {
                    return saslClient.evaluateChallenge(challenge);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof SaslException) {
                throw (SaslException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }
    }

    //TODO I don't like the indirect tests having to pass in a callback handler to get this information
    private static class IndirectCallbackHandler implements CallbackHandler {
        private final String bindingType;
        private final byte[] bindingData;

        private IndirectCallbackHandler(String bindingType, byte[] bindingData) {
            this.bindingType = bindingType;
            this.bindingData = bindingData;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof ChannelBindingCallback) {
                    final ChannelBindingCallback channelBindingCallback = (ChannelBindingCallback) callback;
                    channelBindingCallback.setBindingType(bindingType);
                    channelBindingCallback.setBindingData(bindingData);
                }
            }
        }
    };
}
