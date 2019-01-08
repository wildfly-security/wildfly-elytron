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

import org.wildfly.security.WildFlyElytronCredentialStoreProvider;
import org.wildfly.security.WildFlyElytronKeyProvider;
import org.wildfly.security.WildFlyElytronKeyStoreProvider;
import org.wildfly.security.WildFlyElytronPasswordProvider;
import org.wildfly.security.WildFlyElytronSaslAnonymousProvider;
import org.wildfly.security.WildFlyElytronSaslDigestProvider;
import org.wildfly.security.WildFlyElytronSaslEntityProvider;
import org.wildfly.security.WildFlyElytronSaslExternalProvider;
import org.wildfly.security.WildFlyElytronSaslGs2Provider;
import org.wildfly.security.WildFlyElytronSaslGssapiProvider;
import org.wildfly.security.WildFlyElytronSaslLocalUserProvider;
import org.wildfly.security.WildFlyElytronSaslOAuth2Provider;
import org.wildfly.security.WildFlyElytronSaslOTPProvider;
import org.wildfly.security.WildFlyElytronSaslPlainProvider;
import org.wildfly.security.WildFlyElytronSaslScramProvider;

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

    final boolean elytronProviderStaticallyAdded;

    public ProviderServiceLoaderSupplier(final ClassLoader classLoader) {
        this(classLoader, false);
    }

    public ProviderServiceLoaderSupplier(final ClassLoader classLoader, final boolean elytronProviderStaticallyAdded) {
        super(Provider.class, classLoader);
        this.elytronProviderStaticallyAdded = elytronProviderStaticallyAdded;
    }

    Provider[] loadServices(final Class<Provider> service, final ClassLoader classLoader) {
        Provider[] providers = INSTALLED_PROVIDERS.get();
        Set<Class<?>> installedProvidersSet = new HashSet<>((providers != null ? providers.length : 0) + (elytronProviderStaticallyAdded ? 15 : 0));
        if (elytronProviderStaticallyAdded) {
            installedProvidersSet.add(WildFlyElytronPasswordProvider.class);
            installedProvidersSet.add(WildFlyElytronCredentialStoreProvider.class);
            installedProvidersSet.add(WildFlyElytronKeyProvider.class);
            installedProvidersSet.add(WildFlyElytronKeyStoreProvider.class);
            installedProvidersSet.add(WildFlyElytronSaslAnonymousProvider.class);
            installedProvidersSet.add(WildFlyElytronSaslDigestProvider.class);
            installedProvidersSet.add(WildFlyElytronSaslEntityProvider.class);
            installedProvidersSet.add(WildFlyElytronSaslExternalProvider.class);
            installedProvidersSet.add(WildFlyElytronSaslGs2Provider.class);
            installedProvidersSet.add(WildFlyElytronSaslGssapiProvider.class);
            installedProvidersSet.add(WildFlyElytronSaslLocalUserProvider.class);
            installedProvidersSet.add(WildFlyElytronSaslOAuth2Provider.class);
            installedProvidersSet.add(WildFlyElytronSaslOTPProvider.class);
            installedProvidersSet.add(WildFlyElytronSaslPlainProvider.class);
            installedProvidersSet.add(WildFlyElytronSaslScramProvider.class);
        }
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
