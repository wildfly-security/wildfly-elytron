/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

import static org.wildfly.security.util.ProviderUtil.INSTALLED_PROVIDERS;

import org.wildfly.security.WildFlyElytronProvider;

import java.security.Provider;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * A supplier which uses a service loader to find all {@link Provider} instances that aren't in the list of
 * installed security providers and returns them as an array. The result is then cached.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.2.2
 */
public class ProviderServiceLoaderSupplier extends ServiceLoaderSupplier<Provider> {

    public ProviderServiceLoaderSupplier(final ClassLoader classLoader) {
        super(Provider.class, classLoader);
    }

    Provider[] loadServices(final Class<Provider> service, final ClassLoader classLoader) {
        Provider[] providers = INSTALLED_PROVIDERS.get();
        Set<Class<?>> installedProvidersSet = new HashSet<>((providers != null ? providers.length : 0) + 1);
        installedProvidersSet.add(WildFlyElytronProvider.class);
        if (providers != null) {
            for (int i = 0; i < providers.length; i++) {
                installedProvidersSet.add(providers[i].getClass());
            }
        }
        ArrayList<Provider> list = new ArrayList<>();
        ServiceLoader<Provider> loader = ServiceLoader.load(service, classLoader);
        Iterator<Provider> iterator = loader.iterator();
        for (;;) try {
            if (! iterator.hasNext()) {
                return list.toArray(new Provider[list.size()]);
            }
            Provider provider = iterator.next();
            if (! installedProvidersSet.contains(provider.getClass())) {
                list.add(provider);
            }
        } catch (ServiceConfigurationError ignored) {
            // explicitly ignored
        }
    }

    public int hashCode() {
        return super.hashCode();
    }

    public boolean equals(final Object obj) {
        return obj instanceof ProviderServiceLoaderSupplier && equals((ProviderServiceLoaderSupplier) obj);
    }

    private boolean equals(final ProviderServiceLoaderSupplier other) {
        return other == this || other.classLoader == classLoader;
    }
}
