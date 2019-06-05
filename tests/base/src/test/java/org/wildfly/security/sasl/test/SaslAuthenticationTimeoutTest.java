/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

import static java.security.AccessController.doPrivileged;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.jboss.threads.JBossThreadFactory;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.digest.DigestServerFactory;
import org.wildfly.security.sasl.digest.WildFlyElytronSaslDigestProvider;
import org.wildfly.security.sasl.util.AuthenticationTimeoutSaslServerFactory;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

import mockit.Mock;
import mockit.MockUp;

/**
 * Tests a successful authentication timeout for a custom executor service and the default executor service.
 *
 * @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */

public class SaslAuthenticationTimeoutTest {

    private static final String DIGEST = SaslMechanismInformation.Names.DIGEST_MD5;
    private static final String AUTHENTICATION_TIMEOUT_MESSAGE = "Authentication mechanism server timed out";

    private static final Provider[] providers = new Provider[] {
            WildFlyElytronSaslDigestProvider.getInstance(),
            WildFlyElytronPasswordProvider.getInstance()
    };

    /*
     * Unable to set custom AUTHENTICATION_TIMEOUT using a property SaslServer factory (see ELY-1815), so using mock
     * function to avoid using default timeout of 150 sec
     */
    private static void mockGetTimeout() {
        Class<?> classToMock;
        try {
            classToMock = Class.forName("org.wildfly.security.sasl.util.AuthenticationTimeoutSaslServerFactory", true, AuthenticationTimeoutSaslServerFactory.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new NoClassDefFoundError(e.getMessage());
        }
        new MockUp<Object>(classToMock) {
            @Mock
            private long getTimeout(final Map<String, ?> props) {
                return 3;
            }
        };
    }

    @BeforeClass
    public static void registerPasswordProvider() {
        mockGetTimeout();
        for (Provider provider : providers) {
            Security.insertProviderAt(provider, 1);
        }
    }

    @AfterClass
    public static void removePasswordProvider() {
        for (Provider provider : providers) {
            Security.removeProvider(provider.getName());
        }
    }

    /**
     * Test a successful timeout using a custom executor service
     */
    @Test
    public void testSuccessfulTimeout() throws Exception {

        final ThreadFactory threadFactory = doPrivileged((PrivilegedAction<JBossThreadFactory>) () -> new JBossThreadFactory(new ThreadGroup("SecurityDomain ThreadGroup"), Boolean.FALSE, null, "%G - %t", null, null));
        final ScheduledThreadPoolExecutor INSTANCE = new ScheduledThreadPoolExecutor(1, threadFactory);
        INSTANCE.setRemoveOnCancelPolicy(true);
        INSTANCE.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);

        try {

            SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                    .setUserName("George")
                    .setPassword("gpwd".toCharArray())
                    .setProtocol("TestProtocol")
                    .setServerName("TestServer")
                    .setScheduledExecutorService(INSTANCE)
                    .addMechanismRealm("TestRealm")
                    .build();

            CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", "TestRealm");
            SaslClient client = Sasl.createSaslClient(new String[]{ DIGEST }, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

            byte[] message = server.evaluateResponse(new byte[0]);
            Thread.sleep(5000);
            message = client.evaluateChallenge(message);
            server.evaluateResponse(message);

            Assert.fail("Expected SaslException not thrown");

        } catch (SaslException expected) {
            Assert.assertTrue(expected.getMessage().contains(AUTHENTICATION_TIMEOUT_MESSAGE));
        }
    }

    /**
     * Test a successful timeout using the default executor service
     */
    @Test
    public void testSuccessfulTimeout_DefaultExecuterService() throws Exception {

        try {

            SaslServer server = new SaslServerBuilder(DigestServerFactory.class, DIGEST)
                    .setUserName("George")
                    .setPassword("gpwd".toCharArray())
                    .setProtocol("TestProtocol")
                    .setServerName("TestServer")
                    .addMechanismRealm("TestRealm")
                    .build();

            CallbackHandler clientCallback = createClearPwdClientCallbackHandler("George", "gpwd", "TestRealm");
            SaslClient client = Sasl.createSaslClient(new String[]{ DIGEST }, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

            byte[] message = server.evaluateResponse(new byte[0]);
            Thread.sleep(5000);
            message = client.evaluateChallenge(message);
            server.evaluateResponse(message);

            Assert.fail("Expected SaslException not thrown");

        } catch (SaslException expected) {
            Assert.assertTrue(expected.getMessage().contains(AUTHENTICATION_TIMEOUT_MESSAGE));
        }

    }

    private static CallbackHandler createClearPwdClientCallbackHandler(final String username, final String password, final String sentRealm) throws Exception {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
            return createClientCallbackHandler(username, passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray())), sentRealm);
        }

    private static CallbackHandler createClientCallbackHandler(String username, Password password, String sentRealm) throws URISyntaxException {
        final AuthenticationContext context = org.wildfly.security.auth.client.AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.empty()
                                .useName(username)
                                .usePassword(password)
                                .useRealm(sentRealm)
                                .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism(SaslMechanismInformation.Names.DIGEST_MD5)));


        return ClientUtils.getCallbackHandler(new URI("seems://irrelevant"), context);
    }

}


