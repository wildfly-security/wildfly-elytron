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

package org.wildfly.sasl.gssapi;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.wildfly.sasl.gssapi.JAASUtil.loginClient;
import static org.wildfly.sasl.gssapi.JAASUtil.loginServer;

import java.io.IOException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.jboss.logging.Logger;
import org.jboss.logmanager.log4j.BridgeRepositorySelector;
import org.wildfly.sasl.test.BaseTestCase;
import org.wildfly.sasl.util.Charsets;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test case for testing GSSAPI authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class GssapiMechanismTest extends BaseTestCase {

    private static Logger log = Logger.getLogger(GssapiMechanismTest.class);

    private static final String GSSAPI = "GSSAPI";

    private static final String QOP_AUTH = "auth";
    private static final String QOP_AUTH_INT = "auth-int";
    private static final String QOP_AUTH_CONF = "auth-conf";

    private static TestKDC testKdc;

    @BeforeClass
    public static void startServers() {
        log.debug("Start");
        new BridgeRepositorySelector().start();
        // new org.jboss.logmanager.log4j.BridgeRepositorySelector().start();

        TestKDC testKdc = new TestKDC();
        testKdc.startDirectoryService();
        testKdc.startKDC();
        GssapiMechanismTest.testKdc = testKdc;
    }

    @AfterClass
    public static void stopServers() {
        if (testKdc != null) {
            testKdc.stopAll();
            testKdc = null;
        }
    }

    /*
     * A trio of tests just to verify that a Subject can be obtained, in the event of a failure if these tests are failing focus
     * here first.
     */

    @Test
    public void obtainServer1Subject() throws Exception {
        Subject subject = loginServer("test_server_1");
        assertNotNull(subject);
    }

    @Test
    public void obtainServer2Subject() throws Exception {
        Subject subject = loginServer("test_server_2");
        assertNotNull(subject);
    }

    @Test
    public void obtainClientSubject() throws Exception {
        Subject subject = loginClient();
        assertNotNull(subject);
    }

    @Test
    public void authenticateClientServer1() throws Exception {
        /*
         * With the JDK supplied mechanism implementations this method can cause a NPE if logging for 'javax.security.sasl' is
         * lower than DEBUG
         */

        testSasl("test_server_1", "test_server_1", false, VerificationMode.NONE);
    }

    // @Test
    // public void authenticateClientServer2() throws Exception {
    // /*
    // * With the JDK supplied mechanism implementations this method can cause a NPE if logging for 'javax.security.sasl' is
    // * lower than DEBUG
    // */
    //
    // testSasl("test_server_2", "test_server_1", false, VerificationMode.NONE);
    // }

    @Test
    public void authenticateClientAndServer() throws Exception {
        testSasl("test_server_1", "test_server_1", true, VerificationMode.NONE);
    }

    @Test
    public void authenticateIntegrityQop() throws Exception {
        testSasl("test_server_1", "test_server_1", false, VerificationMode.INTEGRITY);
    }

    @Test
    public void authenticateConfidentialityQop() throws Exception {
        testSasl("test_server_1", "test_server_1", false, VerificationMode.CONFIDENTIALITY);
    }

    private void testSasl(final String actualServer, final String expectedServer, final boolean authServer,
            final VerificationMode mode) throws Exception {
        Subject clientSubject = loginClient();
        SaslClient client = createClient(clientSubject, expectedServer, authServer, mode.getQop());
        Subject serverSubject = loginServer(actualServer);
        SaslServer server = createServer(serverSubject, mode.getQop());

        try {
            byte[] exchange = new byte[0];
            while (client.isComplete() == false || server.isComplete() == false) {
                exchange = evaluateChallenge(clientSubject, client, exchange);
                if (server.isComplete() == false) {
                    exchange = evaluateResponse(serverSubject, server, exchange);
                }
            }
            assertTrue(client.isComplete());
            assertTrue(server.isComplete());
            assertEquals("Authorization ID", "jduke@WILDFLY.ORG", server.getAuthorizationID());

            assertEquals("Server QOP", mode.getQop(), server.getNegotiatedProperty(Sasl.QOP));
            assertEquals("Client QOP", mode.getQop(), client.getNegotiatedProperty(Sasl.QOP));

            /*
             * In the case of the non-auth only modes verify the mode is operating.
             */

            if (mode != VerificationMode.NONE) {
                testDataExchange(client, server);
            }


        } finally {
            try {
                client.dispose();
                server.dispose();
            } catch (SaslException e) {
                // Don't want disposal to mask any error in the test but do want it to happen.
                e.printStackTrace();
            }
        }
    }

    private void testDataExchange(final SaslClient client, final SaslServer server) throws SaslException {
        byte[] original = "Some Test Data".getBytes(Charsets.UTF_8);
        byte[] backup = "Some Test Data".getBytes(Charsets.UTF_8);
        byte[] fromClient = client.wrap(original, 0, original.length);

        assertTrue("Original data unmodified", Arrays.equals(backup, original));

        byte[] unwrapped = server.unwrap(fromClient, 0, fromClient.length);

        assertTrue("Unwrapped (By Server) matched original", Arrays.equals(unwrapped, original));

        byte[] fromServer = server.wrap(original, 0, original.length);

        assertTrue("Original data unmodified", Arrays.equals(backup, original));

        unwrapped = client.unwrap(fromServer, 0, fromServer.length);

        assertTrue("Unwrapped (By Client) matched original", Arrays.equals(unwrapped, original));
    }

    private SaslClient createClient(final Subject subject, final String expectedServer, final boolean authServer,
            final String qop) throws Exception {

        return Subject.doAs(subject, new PrivilegedExceptionAction<SaslClient>() {

            @Override
            public SaslClient run() throws SaslException {
                Map<String, String> props = new HashMap<String, String>();
                props.put(Sasl.SERVER_AUTH, Boolean.toString(authServer));
                props.put(Sasl.QOP, qop);

                return Sasl.createSaslClient(new String[] { GSSAPI }, null, "sasl", expectedServer, props,
                        new NoCallbackHandler());
            }
        });
    }

    private byte[] evaluateChallenge(final Subject subject, final SaslClient client, final byte[] challenge) throws Exception {
        return Subject.doAs(subject, new PrivilegedExceptionAction<byte[]>() {

            @Override
            public byte[] run() throws Exception {
                return client.evaluateChallenge(challenge);
            }
        });
    }

    private byte[] evaluateResponse(final Subject subject, final SaslServer server, final byte[] response) throws Exception {
        return Subject.doAs(subject, new PrivilegedExceptionAction<byte[]>() {

            @Override
            public byte[] run() throws Exception {
                return server.evaluateResponse(response);
            }
        });
    }

    private SaslServer createServer(final Subject subject, final String qop) throws Exception {

        return Subject.doAs(subject, new PrivilegedExceptionAction<SaslServer>() {

            @Override
            public SaslServer run() throws Exception {
                Map<String, String> props = new HashMap<String, String>();
                props.put(Sasl.QOP, qop);

                return Sasl.createSaslServer(GSSAPI, "sasl", "test_server", props, new AuthorizeOnlyCallbackHandler());
            }
        });
    }

    private enum VerificationMode {

        NONE(QOP_AUTH), INTEGRITY(QOP_AUTH_INT), CONFIDENTIALITY(QOP_AUTH_CONF);

        private final String qop;

        VerificationMode(final String qop) {
            this.qop = qop;
        }

        String getQop() {
            return qop;
        }
    }

    private class NoCallbackHandler implements CallbackHandler {

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            throw new UnsupportedCallbackException(callbacks[0]);
        }

    }

    private class AuthorizeOnlyCallbackHandler implements CallbackHandler {

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback current : callbacks) {
                if (current instanceof AuthorizeCallback) {
                    AuthorizeCallback ac = (AuthorizeCallback) current;
                    ac.setAuthorized(ac.getAuthorizationID().equals(ac.getAuthorizationID()));
                } else {
                    throw new UnsupportedCallbackException(current);
                }
            }

        }

    }

}
