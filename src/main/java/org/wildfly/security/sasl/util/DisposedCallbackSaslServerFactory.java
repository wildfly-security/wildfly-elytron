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

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.security.sasl.SaslException;

import org.wildfly.security.auth.callback.SecurityLayerDisposedCallback;

/**
 * A {@link SaslServerFactory} which detects {@link SaslServer} disposal and calls the callback handler with a
 * {@link SecurityLayerDisposedCallback} instance.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class DisposedCallbackSaslServerFactory implements SaslServerFactory {
    private final SaslServerFactory delegate;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server factory
     */
    public DisposedCallbackSaslServerFactory(final SaslServerFactory delegate) {
        this.delegate = delegate;
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final SaslServer saslServer = delegate.createSaslServer(mechanism, protocol, serverName, props, cbh);
        return new SaslServer() {
            public String getMechanismName() {
                return saslServer.getMechanismName();
            }

            public byte[] evaluateResponse(final byte[] response) throws SaslException {
                return saslServer.evaluateResponse(response);
            }

            public String getAuthorizationID() {
                return saslServer.getAuthorizationID();
            }

            public boolean isComplete() {
                return saslServer.isComplete();
            }

            public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
                return saslServer.unwrap(incoming, offset, len);
            }

            public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
                return saslServer.wrap(outgoing, offset, len);
            }

            public Object getNegotiatedProperty(final String propName) {
                return saslServer.getNegotiatedProperty(propName);
            }

            public void dispose() throws SaslException {
                try {
                    saslServer.dispose();
                } finally {
                    try {
                        cbh.handle(new Callback[] { SecurityLayerDisposedCallback.getInstance() });
                    } catch (Throwable ignored) {
                    }
                }
            }
        };
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        return delegate.getMechanismNames(props);
    }
}
