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

package org.wildfly.security.sasl.scram;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.impl.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.util.AbstractSaslParticipant;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class BasicScramSelfTest extends BaseTestCase {

    private static final Provider passwordProvider = new WildFlyElytronPasswordProvider();

    @BeforeClass
    public static void registerPasswordProvider() {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                Security.insertProviderAt(passwordProvider, 2);
                return null;
            }
        });
    }

    @AfterClass
    public static void removePasswordProvider() {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                Security.removeProvider(passwordProvider.getName());
                return null;
            }
        });
    }

    @Test
    public void testSimpleSha1Authentication() throws Exception {
        final char[] passwordChars = "p4ssw0rd".toCharArray();
        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);
        final SaslClientFactory clientFactory = obtainSaslClientFactory(ScramSaslClientFactory.class);
        assertNotNull(clientFactory);
        PasswordFactory passwordFactory = PasswordFactory.getInstance("clear");
        final Password password = passwordFactory.generatePassword(new ClearPasswordSpec(passwordChars));
        final SaslServer saslServer = serverFactory.createSaslServer(Scram.SCRAM_SHA_1, "test", "localhost", Collections.<String, Object>emptyMap(), new CallbackHandler() {
            public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    if (callback instanceof NameCallback) {
                        final String loginName = ((NameCallback) callback).getName();
                        assertEquals("Wrong login name", "login-name", loginName);
                    } else if (callback instanceof CredentialCallback) {
                        final CredentialCallback credentialCallback = (CredentialCallback) callback;
                        if (credentialCallback.isCredentialSupported(password)) {
                            credentialCallback.setCredential(password);
                        }
                    } else {
                        CallbackUtil.unsupported(callback);
                    }
                }
            }
        });
        assertNotNull(saslServer);
        assertTrue(saslServer instanceof ScramSaslServer);
        final SaslClient saslClient = clientFactory.createSaslClient(new String[] { Scram.SCRAM_SHA_1 }, "user", "test", "localhost", Collections.<String, Object>emptyMap(), new CallbackHandler() {
            public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    if (callback instanceof NameCallback) {
                        ((NameCallback) callback).setName("login-name");
                    } else if (callback instanceof CredentialCallback) {
                        final CredentialCallback credentialCallback = (CredentialCallback) callback;
                        if (credentialCallback.isCredentialSupported(password)) {
                            credentialCallback.setCredential(password);
                        }
                    } else if (callback instanceof PasswordCallback) {
                        ((PasswordCallback) callback).setPassword(passwordChars);
                    } else {
                        CallbackUtil.unsupported(callback);
                    }
                }
            }
        });
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof ScramSaslClient);
        byte[] message = AbstractSaslParticipant.NO_BYTES;
        // start it
        do {
            message = saslClient.evaluateChallenge(message);
            if (message == null) break;
            message = saslServer.evaluateResponse(message);
        } while (message != null);
    }
}
