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

package org.wildfly.security.provider.util;

import org.wildfly.common.Assert;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * Utilities for dealing with security providers.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ProviderUtil {

    /**
     * A {@link Supplier} to obtain the {@link Provider} array of providers available from {@link Security#getProviders()}.
     */
    public static final Supplier<Provider[]> INSTALLED_PROVIDERS = Security::getProviders;

    /**
     * Find the first provider from the supplier which provides the given service type and algorithm name.  The simple
     * name of the service type class is used to identify the service.
     *
     * If a providerName is specified the match will only be tested against providers with the name specified.
     *
     * @param providerSupplier the provider supplier (must not be {@code null})
     * @param providerName the name of the provider, can be {@code null}
     * @param serviceType the service type as a class name (must not be {@code null})
     * @param algorithm the algorithm name (must not be {@code null})
     * @return the provider, or {@code null} if none is found
     */
    public static Provider findProvider(Supplier<Provider[]> providerSupplier, String providerName, Class<?> serviceType, String algorithm) {
        Assert.checkNotNullParam("serviceType", serviceType);
        return findProvider(providerSupplier, providerName, serviceType.getSimpleName(), algorithm);
    }

    /**
     * Find the first provider from the supplier which provides the given service type and algorithm name.
     *
     * If a providerName is specified the match will only be tested against providers with the name specified.
     *
     * @param providerSupplier the provider supplier (must not be {@code null})
     * @param providerName the name of the provider, can be {@code null}
     * @param serviceType the service type (must not be {@code null})
     * @param algorithm the algorithm name (must not be {@code null})
     * @return the provider, or {@code null} if none is found
     */
    public static Provider findProvider(Supplier<Provider[]> providerSupplier, String providerName, String serviceType, String algorithm) {
        final Provider.Service service = findProviderService(providerSupplier, providerName, serviceType, algorithm);
        return service == null ? null : service.getProvider();
    }

    /**
     * Find a provider service which provides the given service type and algorithm name.
     *
     * If a providerName is specified the match will only be tested against providers with the name specified.
     *
     * @param providerSupplier the provider supplier (must not be {@code null})
     * @param providerName the name of the provider, can be {@code null}
     * @param serviceType the service type (must not be {@code null})
     * @param algorithm the algorithm name (must not be {@code null})
     * @return the provider service, or {@code null} if none is found
     */
    public static Provider.Service findProviderService(Supplier<Provider[]> providerSupplier, String providerName, Class<?> serviceType, String algorithm) {
        Assert.checkNotNullParam("serviceType", serviceType);
        return findProviderService(providerSupplier, providerName, serviceType.getSimpleName(), algorithm);
    }

    /**
     * Find a provider service which provides the given service type and algorithm name.
     *
     * If a providerName is specified the match will only be tested against providers with the name specified.
     *
     * @param providerSupplier the provider supplier (must not be {@code null})
     * @param providerName the name of the provider, can be {@code null}
     * @param serviceType the service type (must not be {@code null})
     * @param algorithm the algorithm name (must not be {@code null})
     * @return the provider service, or {@code null} if none is found
     */
    public static Provider.Service findProviderService(Supplier<Provider[]> providerSupplier, String providerName, String serviceType, String algorithm) {
        Assert.checkNotNullParam("providerSupplier", providerSupplier);
        Assert.checkNotNullParam("serviceType", serviceType);
        Assert.checkNotNullParam("algorithm", algorithm);
        for (Provider provider : providerSupplier.get()) {
            if (providerName == null || providerName.equals(provider.getName())) {
                Provider.Service providerService = provider.getService(serviceType, algorithm);
                if (providerService != null) {
                    return providerService;
                }
            }
        }
        return null;
    }

    /**
     * Find a provider service which matches the given predicate.
     *
     * @param providerSupplier the provider supplier
     * @param matchPredicate the predicate to test
     * @return the provider service, or {@code null} if none is found
     */
    public static Provider.Service findProviderService(Supplier<Provider[]> providerSupplier, Predicate<Provider.Service> matchPredicate) {
        Assert.checkNotNullParam("providerSupplier", providerSupplier);
        Assert.checkNotNullParam("matchPredicate", matchPredicate);
        for (Provider provider : providerSupplier.get()) {
            for (Provider.Service service : provider.getServices()) {
                if (matchPredicate.test(service)) {
                    return service;
                }
            }
        }
        return null;
    }

    /**
     * Create a {@link Supplier} of providers that is an aggregation of the result of multiple suppliers.
     *
     * The aggregation will be performed the first time the supplier is called and the results cached.
     *
     * @param suppliers the suppliers to aggregate.
     * @return A supplier which will return an aggregation of all of the suppliers.
     */
    public static Supplier<Provider[]> aggregate(final Supplier<Provider[]>... suppliers) {
        Assert.checkNotNullParam("suppliers", suppliers);

        return new Supplier<Provider[]>() {

            private volatile Provider[] result = null;

            @Override
            public Provider[] get() {
                if (result == null) {
                    synchronized (suppliers) {
                        if (result == null) {
                            ArrayList<Provider[]> resolvedProviders = new ArrayList<>(suppliers.length);
                            int count = 0;
                            for (Supplier<Provider[]> current : suppliers) {
                                Provider[] resolved = current.get();
                                count += resolved.length;
                                resolvedProviders.add(resolved);
                            }
                            Provider[] tempResult = new Provider[count];
                            count = 0;
                            for (Provider[] p : resolvedProviders) {
                                System.arraycopy(p, 0, tempResult, (count += p.length) - p.length, p.length);
                            }
                            result = tempResult;
                        }
                    }
                }
                return result.clone();
            }
        };

    }
}
