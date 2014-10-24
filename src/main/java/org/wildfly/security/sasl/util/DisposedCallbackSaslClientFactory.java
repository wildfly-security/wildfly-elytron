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
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.wildfly.security.auth.callback.SecurityLayerDisposedCallback;

/**
 * A {@link SaslClientFactory} which detects {@link SaslClient} disposal and calls the callback handler with a
 * {@link SecurityLayerDisposedCallback} instance.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class DisposedCallbackSaslClientFactory implements SaslClientFactory {
    private final SaslClientFactory delegate;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL client factory
     */
    public DisposedCallbackSaslClientFactory(final SaslClientFactory delegate) {
        this.delegate = delegate;
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final SaslClient saslClient = delegate.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, cbh);
        return new SaslClient() {
            public String getMechanismName() {
                return saslClient.getMechanismName();
            }

            public boolean hasInitialResponse() {
                return saslClient.hasInitialResponse();
            }

            public byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
                return saslClient.evaluateChallenge(challenge);
            }

            public boolean isComplete() {
                return saslClient.isComplete();
            }

            public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
                return saslClient.unwrap(incoming, offset, len);
            }

            public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
                return saslClient.wrap(outgoing, offset, len);
            }

            public Object getNegotiatedProperty(final String propName) {
                return saslClient.getNegotiatedProperty(propName);
            }

            public void dispose() throws SaslException {
                try {
                    saslClient.dispose();
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
