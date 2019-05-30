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
import static org.wildfly.security.http.util.ElytronMessages.log;
import static org.wildfly.security.provider.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * A {@link HttpServerAuthenticationMechanismFactory} that loads factories from a supplied array of {@link Provider} instances.
 * The provider service instances may or may not be cached.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SecurityProviderServerMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private static final String SERVICE_TYPE = HttpServerAuthenticationMechanismFactory.class.getSimpleName();

    private final Supplier<Provider[]> providerSupplier;
    private volatile Provider[] providers;
    private volatile Map<String, List<Service>> services;

    /**
     * Construct a new instance which uses the globally registered {@link Provider} instances.
     */
    public SecurityProviderServerMechanismFactory() {
        this(INSTALLED_PROVIDERS);
    }

    /**
     * Construct a new instance of {@code SecurityProviderServerMechanismFactory}.
     *
     * @param providerSupplier a supplier of providers to use for locating the factories
     */
    public SecurityProviderServerMechanismFactory(Supplier<Provider[]> providerSupplier) {
        this.providerSupplier = checkNotNullParam("providerSupplier", providerSupplier);
    }

    /**
     * Construct a new instance of {@code SecurityProviderServerMechanismFactory}.
     *
     * @param providers the provider instances this factory should use.
     */
    public SecurityProviderServerMechanismFactory(Provider[] providers) {
        this.providerSupplier = null;
        this.providers = checkNotNullParam("providers", providers);
    }

    /**
     * Construct a new instance of {@code SecurityProviderServerMechanismFactory}.
     *
     * @param provider the provider instance this factory should use.
     */
    public SecurityProviderServerMechanismFactory(Provider provider) {
        this(new Provider[] { checkNotNullParam("provider", provider) });
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#getMechanismNames(java.util.Map)
     */
    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        Map<String, List<Service>> services = getServices();
        final Set<String> names;
        if (properties.isEmpty()) {
            /*
             * If no properties are provided that could filter the names return them all.
             */
            names = services.keySet();
        } else {
            names = new LinkedHashSet<>();
            for (List<Service> currentServices : services.values()) {
                for (Service currentService : currentServices) {
                    try {
                        String[] serviceMechNames = ((HttpServerAuthenticationMechanismFactory) currentService.newInstance(null)).getMechanismNames(properties);
                        Collections.addAll(names, serviceMechNames);
                    } catch (NoSuchAlgorithmException e) {
                        log.debug("Unable to create instance", e);
                    }
                }
            }
        }
        if (names.size() == 0 && log.isTraceEnabled()) {
            log.tracef("No %s provided by provider loader in %s: %s", SERVICE_TYPE, getClass().getSimpleName(),
                    Arrays.toString(providerSupplier.get()));
        }
        return names.toArray(new String[names.size()]);
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#createAuthenticationMechanism(java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler) throws HttpAuthenticationException {
        List<Service> services = getServices().get(mechanismName);
        if (services != null) {
            for (Service currentService : services) {
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
        if (log.isTraceEnabled()) {
            log.tracef("No %s provided by provider loader in %s", SERVICE_TYPE, getClass().getSimpleName());
        }
        return null;
    }

    private Map<String, List<Service>> getServices() {
        if (services == null) {
            synchronized(this) {
                if (services == null) {
                    if (providers == null) {
                        providers = providerSupplier.get();
                    }
                    Map<String, List<Service>> services = new HashMap<>();
                    for (Provider provider : providers) {
                        Set<Service> providerServices = provider.getServices();
                        for (Service currentService : providerServices) {
                            if (SERVICE_TYPE.equals(currentService.getType())) {
                                String algorithm = currentService.getAlgorithm();
                                if (services.containsKey(algorithm)) {
                                    services.get(algorithm).add(currentService);
                                } else {
                                    List<Service> serviceList = new ArrayList<>();
                                    serviceList.add(currentService);
                                    services.put(algorithm, serviceList);
                                }
                            }
                        }
                    }
                    this.services = services;
                }
            }
        }

        return services;
    }

}
