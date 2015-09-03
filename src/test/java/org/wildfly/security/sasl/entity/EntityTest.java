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

package org.wildfly.security.sasl.entity;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.wildfly.security.sasl.entity.TrustedAuthority.NameTrustedAuthority;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.sasl.util.AbstractDelegatingSaslClientFactory;
import org.wildfly.security.sasl.util.AbstractDelegatingSaslServerFactory;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.util.CodePointIterator;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

/**
 * Client and server side tests for the ISO/IEC 9798-3 authentication SASL mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@RunWith(JMockit.class)
public class EntityTest extends BaseTestCase {

    private static final String SERVER_KEYSTORE_FILENAME = "/server.keystore";
    private static final String CLIENT_KEYSTORE_FILENAME = "/client.keystore";
    private static final String SERVER_TRUSTSTORE_FILENAME = "/server.truststore";
    private static final String CLIENT_TRUSTSTORE_FILENAME = "/client.truststore";
    private static final String SERVER_KEYSTORE_ALIAS = "testserver1";
    private static final String CLIENT_KEYSTORE_ALIAS = "testclient1";
    private static final String WRONG_KEYSTORE_ALIAS = "wrongone";
    private static final String KEYSTORE_TYPE = "JKS";
    private static final char[] KEYSTORE_PASSWORD = "password".toCharArray();
    private File serverKeyStore = null;
    private File clientKeyStore = null;
    private File serverTrustStore = null;
    private File clientTrustStore = null;
    private File workingDir = null;

    @Before
    public void beforeTest() throws IOException {
        workingDir = getWorkingDir();
        serverKeyStore = copyKeyStore(SERVER_KEYSTORE_FILENAME);
        clientKeyStore = copyKeyStore(CLIENT_KEYSTORE_FILENAME);
        serverTrustStore = copyKeyStore(SERVER_TRUSTSTORE_FILENAME);
        clientTrustStore = copyKeyStore(CLIENT_TRUSTSTORE_FILENAME);
    }

    @After
    public void afterTest() {
        serverKeyStore.delete();
        serverKeyStore = null;
        clientKeyStore.delete();
        clientKeyStore = null;
        serverTrustStore.delete();
        serverTrustStore = null;
        clientTrustStore.delete();
        clientTrustStore = null;
        workingDir.delete();
        workingDir = null;
    }

    @Test
    public void testServerAuthIndirect_Server() throws Exception {
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties are set, an appropriate EntitySaslServer should be returned
        SaslServer server = Sasl.createSaslServer(SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC, "TestProtocol", "TestServer", props, null);
        assertEquals(EntitySaslServer.class, server.getClass());
        assertEquals(SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC, server.getMechanismName());

        // If we set SERVER_AUTH to true even though a unilateral mechanism is specified, no server should be returned
        props.put(Sasl.SERVER_AUTH, Boolean.toString(true));
        server = Sasl.createSaslServer(SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC, "TestProtocol", "TestServer", props, null);
        assertNull(server);
    }

    @Test
    public void testServerAuthDirect_Server() {
        SaslServerFactory factory = obtainSaslServerFactory(EntitySaslServerFactory.class);
        assertNotNull("SaslServerFactory not registered", factory);

        String[] mechanisms;
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties set
        mechanisms = factory.getMechanismNames(props);
        assertMechanisms(new String[]{
                SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC, SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC, SaslMechanismInformation.Names.IEC_ISO_9798_U_DSA_SHA1,
                SaslMechanismInformation.Names.IEC_ISO_9798_M_DSA_SHA1, SaslMechanismInformation.Names.IEC_ISO_9798_U_ECDSA_SHA1, SaslMechanismInformation.Names.IEC_ISO_9798_M_ECDSA_SHA1
        }, mechanisms);

        // Request server auth
        props.put(Sasl.SERVER_AUTH, Boolean.toString(true));
        mechanisms = factory.getMechanismNames(props);
        assertMechanisms(new String[]{SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC, SaslMechanismInformation.Names.IEC_ISO_9798_M_DSA_SHA1, SaslMechanismInformation.Names.IEC_ISO_9798_M_ECDSA_SHA1}, mechanisms);
    }

    @Test
    public void testServerAuthIndirect_Client() throws Exception {
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties are set, an appropriate EntitySaslClient should be returned
        SaslClient client = Sasl.createSaslClient(new String[]{ SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC }, "TestUser", "TestProtocol", "TestServer", props, null);
        assertEquals(EntitySaslClient.class, client.getClass());
        assertEquals(SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC, client.getMechanismName());

        // If we set SERVER_AUTH to true even though only unilateral mechanisms are specified, no client should be returned
        props.put(Sasl.SERVER_AUTH, Boolean.toString(true));
        client = Sasl.createSaslClient(new String[]{SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC, SaslMechanismInformation.Names.IEC_ISO_9798_U_DSA_SHA1, SaslMechanismInformation.Names.IEC_ISO_9798_U_ECDSA_SHA1},
                "TestUser", "TestProtocol", "TestServer", props, null);
        assertNull(client);

        // If we set SERVER_AUTH to true, an appropriate EntitySaslClient should be returned
        props.put(Sasl.SERVER_AUTH, Boolean.toString(true));
        client = Sasl.createSaslClient(new String[]{
                SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC, SaslMechanismInformation.Names.IEC_ISO_9798_U_DSA_SHA1,
                SaslMechanismInformation.Names.IEC_ISO_9798_U_ECDSA_SHA1, SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC, SaslMechanismInformation.Names.IEC_ISO_9798_M_DSA_SHA1, SaslMechanismInformation.Names.IEC_ISO_9798_M_ECDSA_SHA1
            },
                "TestUser", "TestProtocol", "TestServer", props, null);
        assertEquals(EntitySaslClient.class, client.getClass());
        assertEquals(SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC, client.getMechanismName());
    }

    @Test
    public void testServerAuthDirect_Client() {
        SaslClientFactory factory = obtainSaslClientFactory(EntitySaslClientFactory.class);
        assertNotNull("SaslClientFactory not registered", factory);

        String[] mechanisms;
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties set
        mechanisms = factory.getMechanismNames(props);
        assertMechanisms(new String[]{
                SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC, SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC, SaslMechanismInformation.Names.IEC_ISO_9798_U_DSA_SHA1,
                SaslMechanismInformation.Names.IEC_ISO_9798_M_DSA_SHA1, SaslMechanismInformation.Names.IEC_ISO_9798_U_ECDSA_SHA1, SaslMechanismInformation.Names.IEC_ISO_9798_M_ECDSA_SHA1
        }, mechanisms);

        // Request server auth
        props.put(Sasl.SERVER_AUTH, Boolean.toString(true));
        mechanisms = factory.getMechanismNames(props);
        assertMechanisms(new String[]{SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC, SaslMechanismInformation.Names.IEC_ISO_9798_M_DSA_SHA1, SaslMechanismInformation.Names.IEC_ISO_9798_M_ECDSA_SHA1}, mechanisms);
    }

    // -- Successful authentication exchanges --

    @Test
    public void testSimpleUnilateralSha1WithRsaAuthentication() throws Exception {

        final SaslServer saslServer = createSaslServer(SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC);
        assertNotNull(saslServer);
        //assertTrue(saslServer instanceof EntitySaslServer);
        assertFalse(saslServer.isComplete());

        final SaslClient saslClient = createSaslClient(new String[] { SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC });

        assertNotNull(saslClient);
        assertTrue(saslClient instanceof EntitySaslClient);
        assertFalse(saslClient.hasInitialResponse());
        assertFalse(saslClient.isComplete());

        byte[] message = saslServer.evaluateResponse(new byte[0]);
        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        message = saslClient.evaluateChallenge(message);
        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        message = saslServer.evaluateResponse(message);
        assertTrue(saslServer.isComplete());
        assertNull(message);
        assertNull(saslClient.evaluateChallenge(message));
        assertTrue(saslClient.isComplete());
        assertEquals("cn=test client 1,ou=jboss,o=red hat,l=raleigh,st=north carolina,c=us", saslServer.getAuthorizationID());
    }

    @Test
    public void testUnilateralSha1WithRsaAuthenticationWithTrustedAuthorities() throws Exception {
        List<TrustedAuthority> trustedAuthorities = new ArrayList<TrustedAuthority>(3);
        trustedAuthorities.add(new NameTrustedAuthority("cn=some authority,ou=jboss,o=red hat,l=raleigh,st=north carolina,c=us"));
        trustedAuthorities.add(new NameTrustedAuthority("cn=test authority,ou=jboss,o=red hat,l=raleigh,st=north carolina,c=us"));
        trustedAuthorities.add(new NameTrustedAuthority("cn=some other authority,ou=jboss,o=red hat,l=raleigh,st=north carolina,c=us"));
        final SaslServer saslServer = createSaslServer(SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC, trustedAuthorities);

        assertNotNull(saslServer);
        assertFalse(saslServer.isComplete());

        final SaslClient saslClient = createSaslClient(new String[]{SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC});

        assertNotNull(saslClient);
        assertTrue(saslClient instanceof EntitySaslClient);
        assertFalse(saslClient.hasInitialResponse());
        assertFalse(saslClient.isComplete());

        byte[] message = saslServer.evaluateResponse(new byte[0]);
        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        message = saslClient.evaluateChallenge(message);
        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        message = saslServer.evaluateResponse(message);
        assertTrue(saslServer.isComplete());
        assertNull(message);
        assertNull(saslClient.evaluateChallenge(message));
        assertTrue(saslClient.isComplete());
        assertEquals("cn=test client 1,ou=jboss,o=red hat,st=north carolina,c=us", saslServer.getAuthorizationID());
    }

    @Test
    public void testUnilateralSha1WithRsaAuthenticationWithAuthorizationId() throws Exception {
        final SaslServer saslServer = createSaslServer(SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC);
        final SaslClient saslClient = createSaslClient(new String[]{SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC}, "cn=test client 1,ou=jboss,o=red hat,l=raleigh,st=north carolina,c=us", CLIENT_KEYSTORE_ALIAS);

        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        byte[] message = saslServer.evaluateResponse(new byte[0]);
        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        message = saslClient.evaluateChallenge(message);
        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        message = saslServer.evaluateResponse(message);
        assertTrue(saslServer.isComplete());
        assertNull(message);
        assertNull(saslClient.evaluateChallenge(message));
        assertTrue(saslClient.isComplete());
        assertEquals("cn=test client 1,ou=jboss,o=red hat,l=raleigh,st=north carolina,c=us", saslServer.getAuthorizationID());
    }

    @Test
    public void testSimpleMutualSha1WithRsaAuthentication() throws Exception {
        final SaslServer saslServer = createSaslServer(SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC);
        final SaslClient saslClient = createSaslClient(new String[]{SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC});

        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        byte[] message = saslServer.evaluateResponse(new byte[0]);
        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        message = saslClient.evaluateChallenge(message);
        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        message = saslServer.evaluateResponse(message);
        assertNotNull(message);
        message = saslClient.evaluateChallenge(message);
        assertNull(message);
        assertTrue(saslClient.isComplete());
        assertTrue(saslServer.isComplete());
        assertEquals("cn=test client 1,ou=jboss,o=red hat,l=raleigh,st=north carolina,c=us", saslServer.getAuthorizationID());
    }

    @Test
    public void testMutualAuthenticationWithDNSInCNField() throws Exception {
        // Although specifying a DNS name using the Common Name field has been deprecated, it is
        // still used in practice (e.g., see http://tools.ietf.org/html/rfc2818). This test makes
        // sure that general name matching during authentication still works in this case.
        final SaslServer saslServer =
                createSaslServer(
                        SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC, null, "testserver2.example.com", "dnsInCNServer");

        final SaslClient saslClient = createSaslClient(new String[]{SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC}, null, "dnsInCNClient", "testserver2.example.com");
        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        byte[] message = saslServer.evaluateResponse(new byte[0]);
        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        message = saslClient.evaluateChallenge(message);
        assertFalse(saslServer.isComplete());
        assertFalse(saslClient.isComplete());

        message = saslServer.evaluateResponse(message);
        assertNotNull(message);

        message = saslClient.evaluateChallenge(message);
        assertNull(message);
        assertTrue(saslClient.isComplete());
        assertTrue(saslServer.isComplete());
        assertEquals("cn=testclient2.example.com,ou=jboss,o=red hat,l=raleigh,st=north carolina,c=us", saslServer.getAuthorizationID());
    }

    // -- Unsuccessful authentication exchanges --

    @Test
    public void testServerNameMismatch() throws Exception {

        // The server name specified by the client doesn't match the server's actual name
        final SaslServer saslServer = createSaslServer(SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC);
        final SaslClient saslClient = createSaslClient(new String[]{SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC}, null, CLIENT_KEYSTORE_ALIAS, "anotherserver.example.com");

        byte[] message = saslServer.evaluateResponse(new byte[0]);
        try {
            saslClient.evaluateChallenge(message);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testClientNotTrustedByServer() throws Exception {
        final SaslServer saslServer = createSaslServer(SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC, true);
        final SaslClient saslClient = createSaslClient(new String[]{SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC});

        byte[] message = saslServer.evaluateResponse(new byte[0]);
        message = saslClient.evaluateChallenge(message);
        try {
            saslServer.evaluateResponse(message);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testServerNotTrustedByClient() throws Exception {
        final SaslServer saslServer = createSaslServer(SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC);
        final SaslClient saslClient = createSaslClient(new String[]{SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC}, true);
        byte[] message = saslServer.evaluateResponse(new byte[0]);
        message = saslClient.evaluateChallenge(message);
        message = saslServer.evaluateResponse(message);
        try {
            saslClient.evaluateChallenge(message);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testClientPrivateKeyPublicKeyMismatch() throws Exception {
        final SaslServer saslServer = createSaslServer(SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC);
        // A certificate that does not correspond to the client's private key will be used
        final SaslClient saslClient = createWrongCertSaslClient(new String[]{SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC});

        byte[] message = saslServer.evaluateResponse(new byte[0]);
        message = saslClient.evaluateChallenge(message);
        try {
            saslServer.evaluateResponse(message);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testServerPrivateKeyPublicKeyMismatch() throws Exception {

        // A certificate that does not correspond to the server's private key will be used
        final SaslServer saslServer = createSaslServer(
                SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC, new WrongServerCertChainDecorator());
        final SaslClient saslClient = createSaslClient(new String[]{SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC}, null, CLIENT_KEYSTORE_ALIAS, "");

        byte[] message = saslServer.evaluateResponse(new byte[0]);
        message = saslClient.evaluateChallenge(message);
        message = saslServer.evaluateResponse(message);
        try {
            saslClient.evaluateChallenge(message);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
        }
    }

    @Test
    public void testRfc3163Example() throws Exception {
        // This test uses the example from page 10 in RFC 3163 (https://tools.ietf.org/html/rfc3163#section-5)
        mockRandom(new byte[]{18, 56, -105, 88, 121, -121, 71, -104});

        final SaslServer saslServer = createSaslServer(SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC, null, "", SERVER_KEYSTORE_ALIAS);
        assertNotNull(saslServer);
        assertFalse(saslServer.isComplete());

        byte[] tokenBA1 = saslServer.evaluateResponse(new byte[0]);
        byte[] expectedTokenBA1 = CodePointIterator.ofString("MAoECBI4l1h5h0eY").base64Decode().drain();
        assertArrayEquals(expectedTokenBA1, tokenBA1);
        assertFalse(saslServer.isComplete());

        byte[] tokenAB = CodePointIterator.ofString("MIIBAgQIIxh5I0h5RYegD4INc2FzbC1yLXVzLmNvbaFPFk1odHRwOi8vY2VydHMtci11cy5jb20vY2VydD9paD1odmNOQVFFRkJRQURnWUVBZ2hBR2hZVFJna0ZqJnNuPUVQOXVFbFkzS0RlZ2pscjCBkzANBgkqhkiG9w0BAQUFAAOBgQCkuC2GgtYcxGG1NEzLA4bh5lqJGOZySACMmc+mDrV7A7KAgbpO2OuZpMCl7zvNt/L3OjQZatiX8d1XbuQ40l+g2TJzJt06o7ogomxdDwqlA/3zp2WMohlI0MotHmfDSWEDZmEYDEA3/eGgkWyi1v1lEVdFuYmrTr8E4wE9hxdQrA==").base64Decode().drain();
        try {
            saslServer.evaluateResponse(tokenAB);
            fail("Expected SaslException not thrown");
        } catch (SaslException expected) {
            // The example specifies the client's certificate using a fake URL (http://certs-r-us.com/cert?ih=hvcNAQEFBQADgYEAghAGhYTRgkFj&sn=EP9uElY3KDegjlr)
            // so we can actually make use of it.
            assertTrue(expected.getCause().getMessage().contains("certificate"));
        }
        assertFalse(saslServer.isComplete());
    }

    private static File getWorkingDir() {
        File workingDir = new File("./target/keystore");
        if (workingDir.exists() == false) {
            workingDir.mkdirs();
        }
        return workingDir;
    }

    private File copyKeyStore(String keyStoreFileName) throws IOException {
        File keyStore = new File(workingDir, keyStoreFileName);
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(keyStore);
            IOUtils.copy(getClass().getResourceAsStream(keyStoreFileName), fos);
        } finally {
            safeClose(fos);
        }
        return keyStore;
    }

    private void safeClose(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable ignored) {}
        }
    }

    private void mockRandom(final byte[] randomStr){
        new MockUp<EntityUtil>(){
            @Mock
            byte[] generateRandomString(int length, Random random){
                return randomStr;
            }
        };
    }

    private KeyStore loadKeyStore(File keyStore) throws IOException, GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(keyStore);
            ks.load(fis, KEYSTORE_PASSWORD);
        } finally {
            safeClose(fis);
        }
        return ks;
    }

    private SaslServer createSaslServer(String mechanism) throws Exception {
        return createSaslServer(mechanism, null, "testserver1.example.com", SERVER_KEYSTORE_ALIAS);
    }

    private SaslServer createSaslServer(String mechanism, List<TrustedAuthority> trustedAuthorities) throws Exception {
        return createSaslServer(mechanism, trustedAuthorities, "testserver1.example.com", SERVER_KEYSTORE_ALIAS);
    }

    private SaslServer createSaslServer(String mechanism, boolean noTrustStore) throws Exception {
        return createSaslServer(mechanism, null, "testserver1.example.com", SERVER_KEYSTORE_ALIAS, noTrustStore, null);
    }

    private SaslServer createSaslServer(String mechanism, SaslServerBuilder.ExtraDecorator extraDecorator) throws Exception {
        return createSaslServer(mechanism, null, "testserver1.example.com", SERVER_KEYSTORE_ALIAS, false, extraDecorator);
    }

    private SaslServer createSaslServer(String mechanism, List<TrustedAuthority> trustedAuthorities,
                                        String serverName, String keyStoreAlias) throws Exception {
        return createSaslServer(mechanism, trustedAuthorities, serverName, keyStoreAlias, false, null);
    }

    private SaslServer createSaslServer(String mechanism, List<TrustedAuthority> trustedAuthorities,
                                        String serverName, String keyStoreAlias, boolean noTrustStore,
                                        SaslServerBuilder.ExtraDecorator extraDecorator) throws Exception {
        return new SaslServerBuilder(EntitySaslServerFactory.class, mechanism)
                .setProtocol("test")
                .setServerName(serverName)
                .setEntityInformation(
                        trustedAuthorities,
                        noTrustStore ? null : loadKeyStore(serverTrustStore),
                        loadKeyStore(serverKeyStore),
                        keyStoreAlias,
                        KEYSTORE_PASSWORD)
                .build(extraDecorator);
    }

    private SaslClient createSaslClient(String[] mechanisms) throws Exception {
        return createSaslClient(mechanisms, null, CLIENT_KEYSTORE_ALIAS);
    }

    private SaslClient createSaslClient(String[] mechanisms, boolean noTrustStore) throws Exception {
        return createSaslClient(mechanisms, null, CLIENT_KEYSTORE_ALIAS, "testserver1.example.com", noTrustStore, false);
    }

    private SaslClient createSaslClient(String[] mechanisms, String authorizationId, String keyStoreAlias) throws Exception {
        return createSaslClient(mechanisms, authorizationId, keyStoreAlias, "testserver1.example.com");
    }

    private SaslClient createSaslClient(String[] mechanisms, String authorizationId, String keyStoreAlias, String serverName) throws Exception {
        return createSaslClient(mechanisms, authorizationId, keyStoreAlias, serverName, false, false);
    }

    private SaslClient createWrongCertSaslClient(String[] mechanisms) throws Exception {
        return createSaslClient(mechanisms, null, CLIENT_KEYSTORE_ALIAS, "testserver1.example.com", false, true);
    }

    private SaslClient createSaslClient(String[] mechanisms, String authorizationId, String keyStoreAlias,
                                        String serverName, boolean noTrustStore, boolean wrongCert) throws Exception {
        final CallbackHandler cbh = createClientCallbackHandler(mechanisms, authorizationId);
        SaslClientFactory clientFactory = obtainSaslClientFactory(EntitySaslClientFactory.class);
        assertNotNull(clientFactory);

        if (wrongCert) {
            clientFactory = new WrongClientCertChainSaslClientFactory(clientFactory);
        }

        clientFactory = new ConfiguredEntitySaslClientFactory(
                clientFactory,
                noTrustStore ? null : loadKeyStore(clientTrustStore),
                loadKeyStore(clientKeyStore),
                keyStoreAlias,
                KEYSTORE_PASSWORD);

        return clientFactory.createSaslClient(mechanisms, null, "test", serverName, Collections.emptyMap(), cbh);
    }


    private CallbackHandler createClientCallbackHandler(final String[] mechanisms, final String authorizationId) throws Exception {
        AuthenticationConfiguration config = AuthenticationConfiguration.EMPTY
                .allowSaslMechanisms(mechanisms);
        if (authorizationId != null) {
            config = config.useAuthorizationName(authorizationId);
        }
        final AuthenticationContext context = AuthenticationContext.empty().with(MatchRule.ALL, config);

        return ClientUtils.getCallbackHandler(new URI("remote://localhost"), context);
    }

    private class WrongClientCertChainSaslClientFactory extends AbstractDelegatingSaslClientFactory {
        public WrongClientCertChainSaslClientFactory(SaslClientFactory delegate) {
            super(delegate);
        }

        @Override
        public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
            return super.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, callbacks -> {
                ArrayList<Callback> list = new ArrayList<>(Arrays.asList(callbacks));
                final Iterator<Callback> iterator = list.iterator();
                while (iterator.hasNext()) {
                    Callback callback = iterator.next();
                    try {
                        if (callback instanceof CredentialCallback) {
                            final CredentialCallback credentialCallback = (CredentialCallback) callback;
                            for (Class<?> allowedType : credentialCallback.getAllowedTypes()) {
                                //Load the wrong cert chain to be returned to the client
                                if (allowedType == X509Certificate[].class) {
                                    Certificate[] certChain;
                                    certChain = loadKeyStore(serverKeyStore).getCertificateChain(WRONG_KEYSTORE_ALIAS);
                                    credentialCallback.setCredential(Arrays.copyOf(certChain, certChain.length, X509Certificate[].class));
                                    iterator.remove();
                                    break;
                                }
                            }
                        }
                    } catch (GeneralSecurityException e) {
                        SaslException ex = new SaslException(e.getLocalizedMessage());
                        ex.initCause(e);
                        throw ex;
                    }
                }
                if (!list.isEmpty()) {
                    cbh.handle(list.toArray(new Callback[list.size()]));
                }
            });
        }
    }

    private class WrongServerCertChainDecorator implements SaslServerBuilder.ExtraDecorator {

        @Override
        public SaslServerFactory decorate(SaslServerFactory factory) {
            return new AbstractDelegatingSaslServerFactory(factory) {
                @Override
                public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
                    return super.createSaslServer(mechanism, protocol, serverName, props, callbacks -> {
                        ArrayList<Callback> list = new ArrayList<>(Arrays.asList(callbacks));
                        final Iterator<Callback> iterator = list.iterator();
                        while (iterator.hasNext()) {
                            Callback callback = iterator.next();
                            try {
                                if (callback instanceof CredentialCallback) {
                                    final CredentialCallback credentialCallback = (CredentialCallback) callback;
                                    for (Class<?> allowedType : credentialCallback.getAllowedTypes()) {
                                        //Load the wrong cert chain to be returned to the client
                                        if (allowedType == X509Certificate[].class) {
                                            Certificate[] certChain;
                                            certChain = loadKeyStore(serverKeyStore).getCertificateChain(WRONG_KEYSTORE_ALIAS);
                                            credentialCallback.setCredential(Arrays.copyOf(certChain, certChain.length, X509Certificate[].class));
                                            iterator.remove();
                                            break;
                                        }
                                    }
                                }
                            } catch (GeneralSecurityException e) {
                                SaslException ex = new SaslException(e.getLocalizedMessage());
                                ex.initCause(e);
                                throw ex;
                            }
                        }
                        if (!list.isEmpty()) {
                            cbh.handle(list.toArray(new Callback[list.size()]));
                        }
                    });
                }
            };
        }
    }
}
