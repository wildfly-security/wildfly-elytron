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

package org.wildfly.security.sasl.gssapi.compatibility;

import java.io.IOException;
import java.security.AccessController;
import java.security.NoSuchProviderException;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.wildfly.security.sasl.WildFlySaslProvider;
import org.wildfly.security.sasl.gssapi.BaseGssapiTests;
import org.wildfly.security.sasl.gssapi.JAASUtil;
import org.wildfly.security.sasl.gssapi.TestKDC;

/*
 * Every GSSAPI compatibility test must be in standalone test class because Random instances
 * must be created for every test run new to ensure stable assertable output.
 */
@RunWith(JMockit.class)
public abstract class AbstractTest {

    protected boolean wildfly = true; // if test should be applied to WildFly or JDK SASL implementation

    protected static TestKDC testKdc;
    protected SaslServer server;
    protected SaslClient client;
    protected Subject clientSubject;
    protected Subject serverSubject;
    protected byte[] exchange;
    protected byte[] message;
    protected byte[] wrappedMessage;
    protected byte[] badMessage;

    private static final Provider wildFlySaslProvider = new WildFlySaslProvider();

    @BeforeClass
    public static void registerProvider() {
        AccessController.doPrivileged(new PrivilegedAction<Integer>() {
            public Integer run() {
                return Security.insertProviderAt(wildFlySaslProvider, 1);
            }
        });
    }

    @AfterClass
    public static void removeProvider() {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                Security.removeProvider(wildFlySaslProvider.getName());
                return null;
            }
        });
    }

    @BeforeClass
    public static void installMockClasses() throws Exception {
        new SystemMock();
        new SecureRandomMock();
    }

    @Before
    public void init() throws Exception {

        testKdc = new TestKDC();
        testKdc.startDirectoryService();
        testKdc.startKDC();

        clientSubject = JAASUtil.loginClient();
        serverSubject = JAASUtil.loginServer();

    }

    @After
    public void dispose() throws Exception {
        if(client != null) client.dispose();
        if(server != null) server.dispose();
        if(testKdc != null) testKdc.stopAll();
    }

    public static class SystemMock extends MockUp<System> {
        @Mock
        public long currentTimeMillis(){
            return 123;
        }
        @Mock
        public long nanoTime(){
            return 1234;
        }
    }

    public static class SecureRandomMock extends MockUp<SecureRandom> {
        @Mock
        public void nextBytes(byte[] bytes){
            new Random().nextBytes(bytes);
        }
    }

    protected byte[] evaluateByServer(final byte[] exchange) throws PrivilegedActionException {
        return Subject.doAs(serverSubject, new PrivilegedExceptionAction<byte[]>() {
            public byte[] run() throws Exception {
                return server.evaluateResponse(exchange);
            }
        });
    }

    protected byte[] evaluateByClient(final byte[] exchange) throws PrivilegedActionException {
        return Subject.doAs(clientSubject, new PrivilegedExceptionAction<byte[]>(){
            public byte[] run() throws Exception {
                return client.evaluateChallenge(exchange);
            }
        });
    }

    protected SaslClientFactory findSaslClientFactory(final boolean wildFlyProvider) throws Exception {
        Provider p = findProvider("SaslClientFactory.GSSAPI", wildFlyProvider);
        String factoryName = (String) p.get("SaslClientFactory.GSSAPI");
        return (SaslClientFactory) BaseGssapiTests.class.getClassLoader().loadClass(factoryName).newInstance();
    }

    protected SaslServerFactory findSaslServerFactory(final boolean wildFlyProvider) throws Exception {
        Provider p = findProvider("SaslServerFactory.GSSAPI", wildFlyProvider);
        String factoryName = (String) p.get("SaslServerFactory.GSSAPI");
        return (SaslServerFactory) BaseGssapiTests.class.getClassLoader().loadClass(factoryName).newInstance();
    }

    protected Provider findProvider(final String filter, final boolean wildFlyProvider) throws Exception {
        Provider[] providers = Security.getProviders(filter);
        for (Provider current : providers) {
            if (wildFlyProvider && current instanceof WildFlySaslProvider) {
                return current;
            }
            if (!wildFlyProvider && !(current instanceof WildFlySaslProvider)) {
                return current;
            }
        }
        throw new NoSuchProviderException("Provider not found (filter="+filter+",wildFly="+Boolean.toString(wildFlyProvider)+")");
    }

    protected class AuthorizeOnlyCallbackHandler implements CallbackHandler {
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

    protected class NoCallbackHandler implements CallbackHandler {
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            throw new UnsupportedCallbackException(callbacks[0]);
        }
    }
}
