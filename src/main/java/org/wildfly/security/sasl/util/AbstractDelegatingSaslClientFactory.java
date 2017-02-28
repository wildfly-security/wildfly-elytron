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

/**
 * An abstract base for {@link SaslClientFactory} instances which delegate to another {@code SaslClientFactory}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractDelegatingSaslClientFactory implements SaslClientFactory {

    /**
     * The delegate {@code SaslClientFactory}.
     */
    protected final SaslClientFactory delegate;

    private int hashCode;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate client factory
     */
    protected AbstractDelegatingSaslClientFactory(final SaslClientFactory delegate) {
        this.delegate = delegate;
    }

    /**
     * Determine whether this chain of delegating factories delegates through an instance of the given class.
     *
     * @param factoryClass the SASL client factory class
     * @return {@code true} if this chain delegates through the factory class, {@code false} otherwise
     */
    public final boolean delegatesThrough(Class<? extends SaslClientFactory> factoryClass) {
        return factoryClass != null && delegatesThroughNN(factoryClass);
    }

    boolean delegatesThroughNN(Class<? extends SaslClientFactory> factoryClass) {
        return factoryClass.isInstance(this) || delegate instanceof AbstractDelegatingSaslClientFactory && ((AbstractDelegatingSaslClientFactory) delegate).delegatesThroughNN(factoryClass);
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        return delegate.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, cbh);
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        return delegate.getMechanismNames(props);
    }

    public boolean equals(final Object other) {
        return other instanceof AbstractDelegatingSaslClientFactory && equals((AbstractDelegatingSaslClientFactory) other);
    }

    public boolean equals(final AbstractDelegatingSaslClientFactory other) {
        return this == other || other != null && delegate.equals(other.delegate);
    }

    public final int hashCode() {
        int hashCode = this.hashCode;
        if (hashCode == 0) {
            hashCode = calculateHashCode();
            if (hashCode == 0) hashCode = 1;
            return this.hashCode = hashCode;
        }
        return hashCode;
    }

    /**
     * Perform the calculation of the hash code of this factory.
     *
     * @return the calculated hash code
     */
    protected int calculateHashCode() {
        return delegate.hashCode();
    }
}
