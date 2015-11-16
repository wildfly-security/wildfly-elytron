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

package org.wildfly.security.util;

import java.security.Provider;
import java.util.function.Predicate;
import java.util.function.Supplier;

import org.wildfly.common.Assert;

/**
 * Utilities for dealing with security providers.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ProviderUtil {

    /**
     * Find the first provider from the supplier which provides the given service type and algorithm name.  The simple
     * name of the service type class is used to identify the service.
     *
     * @param providerSupplier the provider supplier (must not be {@code null})
     * @param serviceType the service type as a class name (must not be {@code null})
     * @param algorithm the algorithm name (must not be {@code null})
     * @return the provider, or {@code null} if none is found
     */
    public static Provider findProvider(Supplier<Provider[]> providerSupplier, Class<?> serviceType, String algorithm) {
        Assert.checkNotNullParam("serviceType", serviceType);
        return findProvider(providerSupplier, serviceType.getSimpleName(), algorithm);
    }

    /**
     * Find the first provider from the supplier which provides the given service type and algorithm name.
     *
     * @param providerSupplier the provider supplier (must not be {@code null})
     * @param serviceType the service type (must not be {@code null})
     * @param algorithm the algorithm name (must not be {@code null})
     * @return the provider, or {@code null} if none is found
     */
    public static Provider findProvider(Supplier<Provider[]> providerSupplier, String serviceType, String algorithm) {
        final Provider.Service service = findProviderService(providerSupplier, serviceType, algorithm);
        return service == null ? null : service.getProvider();
    }

    /**
     * Find a provider service which provides the given service type and algorithm name.
     *
     * @param providerSupplier the provider supplier (must not be {@code null})
     * @param serviceType the service type (must not be {@code null})
     * @param algorithm the algorithm name (must not be {@code null})
     * @return the provider service, or {@code null} if none is found
     */
    public static Provider.Service findProviderService(Supplier<Provider[]> providerSupplier, Class<?> serviceType, String algorithm) {
        Assert.checkNotNullParam("serviceType", serviceType);
        return findProviderService(providerSupplier, serviceType.getSimpleName(), algorithm);
    }

    /**
     * Find a provider service which provides the given service type and algorithm name.
     *
     * @param providerSupplier the provider supplier (must not be {@code null})
     * @param serviceType the service type (must not be {@code null})
     * @param algorithm the algorithm name (must not be {@code null})
     * @return the provider service, or {@code null} if none is found
     */
    public static Provider.Service findProviderService(Supplier<Provider[]> providerSupplier, String serviceType, String algorithm) {
        Assert.checkNotNullParam("providerSupplier", providerSupplier);
        Assert.checkNotNullParam("serviceType", serviceType);
        Assert.checkNotNullParam("algorithm", algorithm);
        for (Provider provider : providerSupplier.get()) {
            Provider.Service providerService = provider.getService(serviceType, algorithm);
            if (providerService != null) {
                return providerService;
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
}
