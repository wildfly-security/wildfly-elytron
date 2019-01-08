/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.server;

import java.util.Collection;
import java.util.function.UnaryOperator;

/**
 * A generalized mechanism factory which authenticates against a security domain.
 *
 * @param <M> the type of mechanism
 * @param <F> the type of the mechanism's factory
 * @param <E> the mechanism-type-specific exception that may be thrown upon instantiation
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface MechanismAuthenticationFactory<M, F, E extends Exception> {

    /**
     * Get the underlying {@link SecurityDomain} that mechanisms created by this factory will be using for authentication.
     *
     * @return the underlying {@link SecurityDomain} that mechanisms created by this factory will be using for authentication.
     */
    SecurityDomain getSecurityDomain();

    /**
     * Get the actual factory used for instantiation.
     *
     * @return the actual factory (not {@code null})
     */
    F getFactory();

    /**
     * Create the mechanism instance.
     *
     * @param name the mechanism name (must not be {@code null})
     * @param factoryTransformation the transformation to apply to the factory (must not be {@code null})
     * @return the mechanism, or {@code null} if the mechanism with the given name is not supported
     * @throws E if the mechanism instantiation failed
     */
    M createMechanism(String name, UnaryOperator<F> factoryTransformation) throws E;

    /**
     * Create the mechanism instance.
     *
     * @param name the mechanism name (must not be {@code null})
     * @return the mechanism, or {@code null} if the mechanism with the given name is not supported
     * @throws E if the mechanism instantiation failed
     */
    default M createMechanism(String name) throws E {
        return createMechanism(name, UnaryOperator.identity());
    }

    /**
     * Get the collection of mechanism names may be supported by this factory.  The actual set of available mechanisms depends
     * on run-time factors but will generally not be greater than this collection.
     *
     * @return the mechanism names (not {@code null})
     */
    Collection<String> getMechanismNames();

    /**
     * A builder for a {@link MechanismAuthenticationFactory}.
     *
     * @param <M> the type of mechanism
     * @param <F> the type of the mechanism's factory
     * @param <E> the mechanism-type-specific exception that may be thrown upon instantiation
     */
    interface Builder<M, F, E extends Exception> {
        /**
         * Set the security domain to be used for this factory (may not be {@code null}).
         *
         * @param securityDomain the security domain (may not be {@code null})
         * @return this builder
         */
        Builder<M, F, E> setSecurityDomain(SecurityDomain securityDomain);

        /**
         * Set the {@link MechanismConfigurationSelector} for the factory being built.
         *
         * @param mechanismConfigurationSelector the {@link MechanismConfigurationSelector} for the factory being built.
         * @return this builder
         */
        Builder<M, F, E> setMechanismConfigurationSelector(MechanismConfigurationSelector mechanismConfigurationSelector);

        /**
         * Set the mechanism's underlying factory.
         *
         * @param factory the factory (must not be {@code null})
         * @return this builder
         */
        Builder<M, F, E> setFactory(F factory);

        /**
         * Build the mechanism factory.
         *
         * @return the mechanism factory
         */
        MechanismAuthenticationFactory<M, F, E> build();
    }
}
