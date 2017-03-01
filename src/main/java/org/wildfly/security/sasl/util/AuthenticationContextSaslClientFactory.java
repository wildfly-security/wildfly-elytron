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

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.wildfly.common.math.HashMath;
import org.wildfly.security.auth.client.AuthenticationContext;

/**
 * A delegating {@link SaslClientFactory} which establishes a specific {@link AuthenticationContext} for the duration
 * of the authentication process.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AuthenticationContextSaslClientFactory extends AbstractDelegatingSaslClientFactory {
    private final AuthenticationContext context;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL client factory
     */
    public AuthenticationContextSaslClientFactory(final SaslClientFactory delegate) {
        super(delegate);
        context = AuthenticationContext.captureCurrent();
    }

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL client factory
     * @param context the authentication context to use
     */
    public AuthenticationContextSaslClientFactory(final SaslClientFactory delegate, final AuthenticationContext context) {
        super(delegate);
        this.context = context;
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final SaslClient delegate = super.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, cbh);
        if (delegate == null) {
            return null;
        }
        return new AuthenticationContextSaslClient(delegate, context);
    }

    @SuppressWarnings("checkstyle:equalshashcode")
    public boolean equals(final Object other) {
        return other instanceof AuthenticationContextSaslClientFactory && equals((AuthenticationContextSaslClientFactory) other);
    }

    @SuppressWarnings("checkstyle:equalshashcode")
    public boolean equals(final AbstractDelegatingSaslClientFactory other) {
        return other instanceof AuthenticationContextSaslClientFactory && equals((AuthenticationContextSaslClientFactory) other);
    }

    @SuppressWarnings("checkstyle:equalshashcode")
    public boolean equals(final AuthenticationContextSaslClientFactory other) {
        return super.equals(other) && context.equals(other.context);
    }

    protected int calculateHashCode() {
        return HashMath.multiHashOrdered(HashMath.multiHashOrdered(super.calculateHashCode(), getClass().hashCode()), context.hashCode());
    }
}
