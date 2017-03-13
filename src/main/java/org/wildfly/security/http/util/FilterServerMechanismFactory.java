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
package org.wildfly.security.http.util;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * An implementation of {@link HttpServerAuthenticationMechanismFactory} that wraps an existing factory and provides mechanism
 * filtering by name.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class FilterServerMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private final HttpServerAuthenticationMechanismFactory delegate;
    private final Predicate<String> predicate;

    /**
     * Constructs a new instance.
     *
     * @param delegate the {@link HttpServerAuthenticationMechanismFactory} to delegate to.
     * @param predicate mechanism name based predicate to filter available mechanisms.
     */
    public FilterServerMechanismFactory(final HttpServerAuthenticationMechanismFactory delegate, final Predicate<String> predicate) {
        this.delegate = checkNotNullParam("delegate", delegate);
        this.predicate = checkNotNullParam("predicate", predicate);
    }

    /**
     * Construct a new instance that filters from a provided set of mechanism names.
     *
     * @param delegate the {@link HttpServerAuthenticationMechanismFactory} to delegate to.
     * @param include when {@code true} mechanisms will be advertised as available if included in the provided mechanismNames.
     * @param mechanismNames the mechanism names to use as a filter.
     */
    public FilterServerMechanismFactory(final HttpServerAuthenticationMechanismFactory delegate, final boolean include , String ... mechanismNames) {
        this.delegate = checkNotNullParam("delegate", delegate);
        final Set<String> nameSet = new HashSet<>(mechanismNames.length);
        Collections.addAll(nameSet, mechanismNames);

        Predicate<String> predicate = nameSet::contains;
        this.predicate = include ? predicate : predicate.negate();
    }

    /**
     * Construct a new instance that filters from a provided set of mechanism names.
     *
     * @param delegate the {@link HttpServerAuthenticationMechanismFactory} to delegate to.
     * @param include when {@code true} mechanisms will be advertised as available if included in the provided mechanismNames.
     * @param mechanismNames the mechanism names to use as a filter.
     */
    public FilterServerMechanismFactory(final HttpServerAuthenticationMechanismFactory delegate, final boolean include , Collection<String> mechanismNames) {
        this.delegate = checkNotNullParam("delegate", delegate);
        final Set<String> nameSet = new HashSet<>(checkNotNullParam("mechanismNames", mechanismNames));

        Predicate<String> predicate = nameSet::contains;
        this.predicate = include ? predicate : predicate.negate();
    }

    /**
     * Get the available mechanism names after filtering has been performed by the previously provided {@link Predicate}
     *
     * @param properties the {@link Map} of properties to pass into the {@link HttpServerAuthenticationMechanismFactory#getMechanismNames(Map)} call on the delegate.
     * @return The array of filtered mechanism names.
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#getMechanismNames(java.util.Map)
     */
    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        String[] allMechanisms = delegate.getMechanismNames(properties);
        ArrayList<String> filtered = new ArrayList<>(allMechanisms.length);
        for (String current : allMechanisms) {
            if (predicate.test(current)) {
                filtered.add(current);
            }
        }
        if (filtered.size() == 0 && log.isTraceEnabled()) {
            log.tracef("No mechanisms after filtering by %s (original mechanisms: %s)", FilterServerMechanismFactory.class.getSimpleName(), Arrays.toString(allMechanisms));
        }
        return filtered.toArray(new String[filtered.size()]);
    }

    /**
     * Create the requested {@link HttpServerAuthenticationMechanism} provided it is available and allowed by the current filter.
     *
     * @param mechanismName the name of the required mechanism.
     * @param properties the configuration properties to pass in for mechanism creation.
     * @param callbackHandler the {@link CallbackHandler} the mechanism should use for verification.
     * @return The {@link HttpServerAuthenticationMechanism} or {@code null} if not available.
     * @throws HttpAuthenticationException
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#createAuthenticationMechanism(java.lang.String,
     * java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties,
            CallbackHandler callbackHandler) throws HttpAuthenticationException {
        return predicate.test(mechanismName) ? delegate.createAuthenticationMechanism(mechanismName, properties, callbackHandler) : null;
    }

}
