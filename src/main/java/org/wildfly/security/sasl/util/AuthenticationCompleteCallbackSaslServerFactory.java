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

package org.wildfly.security.sasl.util;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.security.sasl.SaslException;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;

/**
 * A {@link SaslServerFactory} which adds {@link AuthenticationCompleteCallback} functionality to a delegate
 * {@code SaslServerFactory}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AuthenticationCompleteCallbackSaslServerFactory implements SaslServerFactory {
    private final SaslServerFactory delegate;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate {@code SaslServerFactory}
     */
    public AuthenticationCompleteCallbackSaslServerFactory(final SaslServerFactory delegate) {
        this.delegate = delegate;
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final SaslServer delegateSaslServer = delegate.createSaslServer(mechanism, protocol, serverName, props, cbh);
        return new SaslServer() {
            private final AtomicBoolean complete = new AtomicBoolean();

            public String getMechanismName() {
                return delegateSaslServer.getMechanismName();
            }

            public String getAuthorizationID() {
                return delegateSaslServer.getAuthorizationID();
            }

            public byte[] evaluateResponse(final byte[] response) throws SaslException {
                try {
                    final byte[] challenge = delegateSaslServer.evaluateResponse(response);
                    if (isComplete() && complete.compareAndSet(false, true)) try {
                        cbh.handle(new Callback[] { new AuthenticationCompleteCallback(true) });
                    } catch (Throwable ignored) {
                    }
                    return challenge;
                } catch (SaslException | RuntimeException | Error e) {
                    if (isComplete() && complete.compareAndSet(false, true)) try {
                        cbh.handle(new Callback[] { new AuthenticationCompleteCallback(false) });
                    } catch (Throwable ignored) {
                    }
                    throw e;
                }
            }

            public boolean isComplete() {
                return delegateSaslServer.isComplete();
            }

            public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
                return delegateSaslServer.unwrap(incoming, offset, len);
            }

            public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
                return delegateSaslServer.wrap(outgoing, offset, len);
            }

            public Object getNegotiatedProperty(final String propName) {
                return delegateSaslServer.getNegotiatedProperty(propName);
            }

            public void dispose() throws SaslException {
                delegateSaslServer.dispose();
            }
        };
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        return delegate.getMechanismNames(props);
    }
}
