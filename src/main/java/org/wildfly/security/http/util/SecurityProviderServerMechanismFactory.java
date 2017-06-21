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

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * A {@link HttpServerAuthenticationMechanismFactory} that loads factories from a supplied array of {@link Provider} instances.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SecurityProviderServerMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private static final String SERVICE_TYPE = HttpServerAuthenticationMechanismFactory.class.getSimpleName();

    private final Supplier<Provider[]> providerSupplier;

    /**
     * Construct a new instance of {@code SecurityProviderServerMechanismFactory}.
     *
     * @param providerSupplier a {@link Supplier<Provider>} to supply the providers to use for locating the factories.
     */
    public SecurityProviderServerMechanismFactory(Supplier<Provider[]> providerSupplier) {
        this.providerSupplier = checkNotNullParam("providerSupplier", providerSupplier);
    }

    /**
     * Construct a new instance which uses the globally registered {@link Provider} instances.
     */
    public SecurityProviderServerMechanismFactory() {
        this(Security::getProviders);
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#getMechanismNames(java.util.Map)
     */
    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        Set<String> names = new LinkedHashSet<>();
        for (Provider current : providerSupplier.get()) {
            Set<Service> services = current.getServices();
            if (services != null) {
                for (Service currentService : services) {
                    if (SERVICE_TYPE.equals(currentService.getType())) {
                        try {
                            String[] serviceMechNames = ((HttpServerAuthenticationMechanismFactory) currentService.newInstance(null)).getMechanismNames(properties);
                            Collections.addAll(names, serviceMechNames);
                        } catch (NoSuchAlgorithmException e) {
                            log.debug("Unable to create instance", e);
                        }
                    }
                }
            }
        }
        if (names.size() == 0 && log.isTraceEnabled()) {
            log.tracef("No %s provided by provider loader in %s: %s", SERVICE_TYPE, getClass().getSimpleName(), Arrays.toString(providerSupplier.get()));
        }
        return names.toArray(new String[names.size()]);
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#createAuthenticationMechanism(java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler) throws HttpAuthenticationException {
        for (Provider current : providerSupplier.get()) {
            Set<Service> services = current.getServices();
            if (services != null) {
                for (Service currentService : services) {
                    if (SERVICE_TYPE.equals(currentService.getType())) {
                        try {
                            HttpServerAuthenticationMechanismFactory factory = (HttpServerAuthenticationMechanismFactory) currentService.newInstance(null);
                            HttpServerAuthenticationMechanism mechanism = factory.createAuthenticationMechanism(mechanismName, properties, callbackHandler);
                            if (mechanism != null) {
                                return mechanism;
                            }
                        } catch (NoSuchAlgorithmException e) {
                            log.debug("Unable to create instance", e);
                        }
                    }
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.tracef("No %s provided by provider loader in %s: %s", SERVICE_TYPE, getClass().getSimpleName(), Arrays.toString(providerSupplier.get()));
        }
        return null;
    }

}
