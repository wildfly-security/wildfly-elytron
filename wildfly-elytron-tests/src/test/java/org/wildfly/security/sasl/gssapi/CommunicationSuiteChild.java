/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.sasl.gssapi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.sasl.gssapi.CommunicationSuiteChild.VerificationMode.CONFIDENTIALITY;
import static org.wildfly.security.sasl.gssapi.CommunicationSuiteChild.VerificationMode.NONE;
import static org.wildfly.security.sasl.gssapi.CommunicationSuiteChild.VerificationMode.INTEGRITY;
import static org.wildfly.security.sasl.gssapi.JaasUtil.loginClient;
import static org.wildfly.security.sasl.gssapi.JaasUtil.loginServer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedAction;
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
import javax.security.auth.login.LoginException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.wildfly.security.WildFlyElytronSaslGssapiProvider;
import org.wildfly.security.sasl.WildFlySasl;

@RunWith(Parameterized.class)
public class CommunicationSuiteChild {

    private static final String TEST_SERVER_1 = "test_server_1";

    private static final String SASL_CLIENT_FACTORY_GSSAPI = "SaslClientFactory.GSSAPI";
    private static final String SASL_SERVER_FACTORY_GSSAPI = "SaslServerFactory.GSSAPI";

    private static final String GSSAPI = "GSSAPI";

    private static final String QOP_AUTH = "auth";
    private static final String QOP_AUTH_INT = "auth-int";
    private static final String QOP_AUTH_CONF = "auth-conf";

    static final String SERVER_KEY_TAB = "serverKeyTab";
    static final String SERVER_UNBOUND_KEY_TAB = "serverUnboundKeyTab";

    private static final Provider wildFlyElytronProvider = WildFlyElytronSaslGssapiProvider.getInstance();

    private static Subject clientSubject;
    private static Subject serverSubject;
    private static Subject unboundServerSubject;

    @Parameterized.Parameter(0)
    public boolean serverElytron;

    @Parameterized.Parameter(1)
    public boolean clientElytron;

    @Parameterized.Parameter(2)
    public boolean authServer;

    @Parameterized.Parameter(3)
    public boolean unbound;

    @Parameterized.Parameter(4)
    public VerificationMode mode;

    @Parameterized.Parameters(name = "serverElytron={0} clientElytron={1} authServer={2} unbound={3} mode={4}")
    public static Iterable<Object[]> serverElytron() {
        System.out.println("Parameters init");
        return Arrays.asList(
                new Object[] {true,  true,  false, false, NONE},
                new Object[] {true,  true,  true,  false, NONE},
                new Object[] {true,  true,  false, false, INTEGRITY},
                new Object[] {true,  true,  false, false, CONFIDENTIALITY},
                new Object[] {true,  true,  false, true,  CONFIDENTIALITY},
                new Object[] {true,  false, false, false, NONE},
                new Object[] {true,  false, true,  false, NONE},
                new Object[] {true,  false, false, false, INTEGRITY},
                new Object[] {true,  false, false, false, CONFIDENTIALITY},
                new Object[] {true,  false, false, true,  CONFIDENTIALITY},
                new Object[] {false, true,  false, false, NONE},
                new Object[] {false, true,  true,  false, NONE},
                new Object[] {false, true,  false, false, INTEGRITY},
                new Object[] {false, true,  false, false, CONFIDENTIALITY},
                new Object[] {false, true,  false, true,  CONFIDENTIALITY},
                new Object[] {false, false, false, false, NONE},
                new Object[] {false, false, true,  false, NONE},
                new Object[] {false, false, false, false, INTEGRITY},
                new Object[] {false, false, false, false, CONFIDENTIALITY},
                new Object[] {false, false, false, true,  CONFIDENTIALITY}
        );
    }

    @BeforeClass
    public static void initialize() throws LoginException {
        clientSubject = loginClient();
        serverSubject = loginServer(GssapiTestSuite.serverKeyTab, false);
        unboundServerSubject = loginServer(GssapiTestSuite.serverUnboundKeyTab, true);
        assertNotNull(clientSubject);
        assertNotNull(serverSubject);
        assertNotNull(unboundServerSubject);

        AccessController.doPrivileged((PrivilegedAction<Integer>) () ->
                Security.insertProviderAt(wildFlyElytronProvider, 1)
        );
    }

    @AfterClass
    public static void destroy() {
        clientSubject = null;
        serverSubject = null;
        unboundServerSubject = null;

        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            Security.removeProvider(wildFlyElytronProvider.getName());
            return null;
        });
    }

    @Test
    public void testSasl() throws Exception {
        SaslClient client = getSaslClient();
        SaslServer server = getSaslServer();

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
            assertEquals("Bound server name", TEST_SERVER_1, server.getNegotiatedProperty(Sasl.BOUND_SERVER_NAME));

            assertEquals("Server QOP", mode.getQop(), server.getNegotiatedProperty(Sasl.QOP));
            assertEquals("Client QOP", mode.getQop(), client.getNegotiatedProperty(Sasl.QOP));

            /*
             * In the case of the non-auth only modes verify the mode is operating:
             *  * messages can be exchanged successfully
             *  * buffer size is negotiated correctly
             */
            if (mode != NONE) {
                assertEquals("Server MAX_BUFFER", "64321", server.getNegotiatedProperty(Sasl.MAX_BUFFER));
                assertEquals("Client MAX_BUFFER", "61234", client.getNegotiatedProperty(Sasl.MAX_BUFFER));

                int serverRawSize = Integer.parseInt((String) server.getNegotiatedProperty(Sasl.RAW_SEND_SIZE));
                int clientRawSize = Integer.parseInt((String) client.getNegotiatedProperty(Sasl.RAW_SEND_SIZE));
                assertTrue("Server RAW_SEND_SIZE", 61000 < serverRawSize && serverRawSize < 61234);
                assertTrue("Client RAW_SEND_SIZE", 64000 < clientRawSize && clientRawSize < 64321);

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
        byte[] original = "Some Test Data".getBytes(StandardCharsets.UTF_8);
        byte[] backup = "Some Test Data".getBytes(StandardCharsets.UTF_8);

        byte[] wrappedFromClient = client.wrap(original, 0, original.length);

        assertTrue("Original data unmodified", Arrays.equals(backup, original));

        byte[] unwrappedFromClient = server.unwrap(wrappedFromClient, 0, wrappedFromClient.length);

        assertTrue("Unwrapped (By Server) matched original", Arrays.equals(unwrappedFromClient, original));

        byte[] wrappedFromServer = server.wrap(original, 0, original.length);

        assertTrue("Original data unmodified", Arrays.equals(backup, original));

        byte[] unwrappedFromServer = client.unwrap(wrappedFromServer, 0, wrappedFromServer.length);

        assertTrue("Unwrapped (By Client) matched original", Arrays.equals(unwrappedFromServer, original));
    }

    private SaslClient getSaslClient() throws Exception {
        SaslClient baseClient = Subject.doAs(clientSubject, (PrivilegedExceptionAction<SaslClient>) this::createClient);
        return new SubjectWrappingSaslClient(baseClient, clientSubject);
    }

    private SaslServer getSaslServer() throws Exception {
        SaslServer baseServer = Subject.doAs(serverSubject, (PrivilegedExceptionAction<SaslServer>) this::createServer);
        return new SubjectWrappingSaslServer(baseServer, unbound ? unboundServerSubject : serverSubject);
    }

    /*
     * Client Creation Methods
     */

    private SaslClient createClient() throws Exception {
        Provider provider = findProvider(SASL_CLIENT_FACTORY_GSSAPI, clientElytron);
        String factoryName = (String) provider.get(SASL_CLIENT_FACTORY_GSSAPI);
        SaslClientFactory factory = Class.forName(factoryName).asSubclass(SaslClientFactory.class).newInstance();

        Map<String, String> props = new HashMap<>();
        props.put(Sasl.SERVER_AUTH, Boolean.toString(authServer));
        props.put(Sasl.QOP, mode.getQop());
        props.put(Sasl.MAX_BUFFER, Integer.toString(61234));
        if (clientElytron && !serverElytron) {
            props.put(WildFlySasl.RELAX_COMPLIANCE, Boolean.TRUE.toString());
        }

        return factory.createSaslClient(new String[] { GSSAPI }, null, "sasl", TEST_SERVER_1, props, new NoCallbackHandler());
    }

    /*
     * Server Creation Methods
     */

    private SaslServer createServer() throws Exception {
        Provider provider = findProvider(SASL_SERVER_FACTORY_GSSAPI, serverElytron);
        String factoryName = (String) provider.get(SASL_SERVER_FACTORY_GSSAPI);
        SaslServerFactory factory = Class.forName(factoryName).asSubclass(SaslServerFactory.class).newInstance();

        Map<String, String> props = new HashMap<>();
        props.put(Sasl.QOP, mode.getQop());
        props.put(Sasl.MAX_BUFFER, Integer.toString(64321));
        if (!clientElytron && serverElytron) {
            props.put(WildFlySasl.RELAX_COMPLIANCE, Boolean.TRUE.toString());
        }

        return factory.createSaslServer(GSSAPI, "sasl", unbound ? null : TEST_SERVER_1, props, new AuthorizeOnlyCallbackHandler());
    }

    /*
     * Provider Methods
     */

    private Provider findProvider(final String filter, final boolean elytronProvider) {
        Provider[] providers = Security.getProviders(filter);
        for (Provider current : providers) {
            if (current instanceof WildFlyElytronSaslGssapiProvider) {
                if (elytronProvider) {
                    return current;
                }
            } else {
                if (! elytronProvider) {
                    return current;
                }
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
                    ac.setAuthorized(ac.getAuthorizationID().equals(ac.getAuthenticationID()));
                } else {
                    throw new UnsupportedCallbackException(current);
                }
            }
        }

    }
}
