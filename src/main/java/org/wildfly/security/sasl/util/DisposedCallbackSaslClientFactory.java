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

import org.wildfly.common.math.HashMath;
import org.wildfly.security.auth.callback.SecurityLayerDisposedCallback;

/**
 * A {@link SaslClientFactory} which detects {@link SaslClient} disposal and calls the callback handler with a
 * {@link SecurityLayerDisposedCallback} instance.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class DisposedCallbackSaslClientFactory extends AbstractDelegatingSaslClientFactory {

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL client factory
     */
    public DisposedCallbackSaslClientFactory(final SaslClientFactory delegate) {
        super(delegate);
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final SaslClient saslClient = delegate.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, cbh);
        return saslClient == null ? null : new AbstractDelegatingSaslClient(saslClient) {
            public void dispose() throws SaslException {
                try {
                    super.dispose();
                } finally {
                    try {
                        cbh.handle(new Callback[] { SecurityLayerDisposedCallback.getInstance() });
                    } catch (Throwable ignored) {
                    }
                }
            }
        };
    }

    @SuppressWarnings("checkstyle:equalshashcode")
    public boolean equals(final Object other) {
        return other instanceof DisposedCallbackSaslClientFactory && equals((DisposedCallbackSaslClientFactory) other);
    }

    @SuppressWarnings("checkstyle:equalshashcode")
    public boolean equals(final AbstractDelegatingSaslClientFactory other) {
        return other instanceof DisposedCallbackSaslClientFactory && equals((DisposedCallbackSaslClientFactory) other);
    }

    @SuppressWarnings("checkstyle:equalshashcode")
    public boolean equals(final DisposedCallbackSaslClientFactory other) {
        return super.equals(other);
    }

    protected int calculateHashCode() {
        return HashMath.multiHashOrdered(super.calculateHashCode(), getClass().hashCode());
    }
}
