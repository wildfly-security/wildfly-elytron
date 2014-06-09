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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.wildfly.sasl.gssapi.JAASUtil.loginClient;
import static org.wildfly.sasl.gssapi.JAASUtil.loginServer;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.Security;
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
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.jboss.logging.Logger;
import org.junit.Test;
import org.wildfly.sasl.WildFlySaslProvider;
import org.wildfly.sasl.test.BaseTestCase;
import org.wildfly.sasl.util.Charsets;

/**
 * Test case for testing GSSAPI authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class BaseGssapiTests extends BaseTestCase {

    private static final String TEST_SERVER_1 = "test_server_1";

    private static final String SASL_CLIENT_FACTORY_GSSAPI = "SaslClientFactory.GSSAPI";
    private static final String SASL_SERVER_FACTORY_GSSAPI = "SaslServerFactory.GSSAPI";

    private static Logger log = Logger.getLogger(BaseGssapiTests.class);

    private static final String GSSAPI = "GSSAPI";

    private static final String QOP_AUTH = "auth";
    private static final String QOP_AUTH_INT = "auth-int";
    private static final String QOP_AUTH_CONF = "auth-conf";

    /*
     * A pair of tests just to verify that a Subject can be obtained, in the event of a failure if these tests are failing focus
     * here first.
     */

    @Test
    public void obtainServer1Subject() throws Exception {
        Subject subject = loginServer();
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

        testSasl(false, VerificationMode.NONE);
    }

    @Test
    public void authenticateClientAndServer() throws Exception {
        testSasl(true, VerificationMode.NONE);
    }

    @Test
    public void authenticateIntegrityQop() throws Exception {
        testSasl(false, VerificationMode.INTEGRITY);
    }

    @Test
    public void authenticateConfidentialityQop() throws Exception {
        testSasl(false, VerificationMode.CONFIDENTIALITY);
    }

    private void testSasl(final boolean authServer, final VerificationMode mode) throws Exception {
        SaslClient client = getSaslClient(authServer, mode);
        SaslServer server = getSaslServer(mode);

        try {
            byte[] exchange = new byte[0];
            while (client.isComplete() == false || server.isComplete() == false) {
                exchange = client.evaluateChallenge(exchange);
                if (server.isComplete() == false) {
                    exchange = server.evaluateResponse(exchange);
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

    protected abstract SaslClient getSaslClient(final boolean authServer, final VerificationMode mode) throws Exception;

    protected abstract SaslServer getSaslServer(final VerificationMode mode) throws Exception;

    /*
     * Client Creation Methods
     */

    protected SaslClient createClient(final Subject subject, final boolean wildFlyProvider, final boolean authServer,
            final VerificationMode mode, final Map<String, String> baseProps) throws SaslException {
        try {
            return Subject.doAs(subject, new PrivilegedExceptionAction<SaslClient>() {

                @Override
                public SaslClient run() throws SaslException {
                    return createClient(wildFlyProvider, authServer, mode, baseProps);
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

    private SaslClient createClient(final boolean wildFlyProvider,  final boolean authServer, final VerificationMode mode, final Map<String, String> baseProps)
            throws SaslException {
        SaslClientFactory factory = findSaslClientFactory(wildFlyProvider);

        Map<String, String> props = new HashMap<String, String>(baseProps);
        props.put(Sasl.SERVER_AUTH, Boolean.toString(authServer));
        props.put(Sasl.QOP, mode.getQop());

        return factory.createSaslClient(new String[] { GSSAPI }, null, "sasl", TEST_SERVER_1, props, new NoCallbackHandler());
    }

    /*
     * Server Creation Methods
     */

    SaslServer createServer(final Subject subject, final boolean wildFlyProvider, final VerificationMode mode, final Map<String, String> baseProps)
            throws SaslException {

        try {
            return Subject.doAs(subject, new PrivilegedExceptionAction<SaslServer>() {

                @Override
                public SaslServer run() throws Exception {
                    return createServer(wildFlyProvider, mode, baseProps);
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

    private SaslServer createServer(final boolean wildFlyProvider, final VerificationMode mode, final Map<String, String> baseProps) throws SaslException {
        SaslServerFactory factory = findSaslServerFactory(wildFlyProvider);

        Map<String, String> props = new HashMap<String, String>(baseProps);
        props.put(Sasl.QOP, mode.getQop());

        return factory.createSaslServer(GSSAPI, "sasl", "test_server", props, new AuthorizeOnlyCallbackHandler());
    }

    /*
     * Provider Methods
     */

    private SaslClientFactory findSaslClientFactory(final boolean wildFlyProvider) {
        Provider p = findProvider(SASL_CLIENT_FACTORY_GSSAPI, wildFlyProvider);

        String factoryName = (String) p.get(SASL_CLIENT_FACTORY_GSSAPI);

        try {
            return (SaslClientFactory) BaseGssapiTests.class.getClassLoader().loadClass(factoryName).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private SaslServerFactory findSaslServerFactory(final boolean wildFlyProvider) {
        Provider p = findProvider(SASL_SERVER_FACTORY_GSSAPI, wildFlyProvider);

        String factoryName = (String) p.get(SASL_SERVER_FACTORY_GSSAPI);

        try {
            return (SaslServerFactory) BaseGssapiTests.class.getClassLoader().loadClass(factoryName).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private Provider findProvider(final String filter, final boolean wildFlyProvider) {
        Provider[] providers = Security.getProviders(filter);
        for (Provider current : providers) {
            if (current instanceof WildFlySaslProvider) {
                if (wildFlyProvider) {
                    return current;
                }
            } else if (wildFlyProvider == false) {
                return current;
            }
        }
        return null;
    }

    enum VerificationMode {

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
