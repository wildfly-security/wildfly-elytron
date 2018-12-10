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

import static org.wildfly.common.Assert.checkNotNullParam;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.security.sasl.SaslException;

/**
 * An abstract base for {@link SaslServerFactory} instances which delegate to another {@code SaslServerFactory}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractDelegatingSaslServerFactory implements SaslServerFactory {

    /**
     * The delegate {@code SaslServerFactory}.
     */
    protected final SaslServerFactory delegate;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate server factory
     */
    protected AbstractDelegatingSaslServerFactory(final SaslServerFactory delegate) {
        this.delegate = checkNotNullParam("delegate", delegate);
    }

    /**
     * Determine whether this chain of delegating factories delegates through an instance of the given class.
     *
     * @param factoryClass the SASL server factory class
     * @return {@code true} if this chain delegates through the factory class, {@code false} otherwise
     */
    public final boolean delegatesThrough(Class<? extends SaslServerFactory> factoryClass) {
        return factoryClass != null && delegatesThroughNN(factoryClass);
    }

    boolean delegatesThroughNN(Class<? extends SaslServerFactory> factoryClass) {
        return factoryClass.isInstance(this) || delegate instanceof AbstractDelegatingSaslServerFactory && ((AbstractDelegatingSaslServerFactory) delegate).delegatesThroughNN(factoryClass);
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        return delegate.createSaslServer(mechanism, protocol, serverName, props, cbh);
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        return delegate.getMechanismNames(props);
    }

    @Override
    public String toString() {
        return super.toString() + "->" + delegate.toString();
    }
}
