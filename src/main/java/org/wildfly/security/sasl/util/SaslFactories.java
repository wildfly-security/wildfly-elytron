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

import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.function.BiPredicate;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.common.Assert;

/**
 * A utility class for discovering SASL client and server factories.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SaslFactories {

    private SaslFactories() {
    }

    private static final SecurityProviderSaslClientFactory providerSaslClientFactory = new SecurityProviderSaslClientFactory(Security::getProviders);
    private static final SecurityProviderSaslServerFactory providerSaslServerFactory = new SecurityProviderSaslServerFactory(Security::getProviders);

    static final String[] NO_STRINGS = new String[0];
    static final String PROVIDER_FILTER_KEY = "org.wildfly.internal.PFK";

    private static final SaslClientFactory EMPTY_SASL_CLIENT_FACTORY = new SaslClientFactory() {
        public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
            return null;
        }

        public String[] getMechanismNames(final Map<String, ?> props) {
            return NO_STRINGS;
        }
    };

    private static final SaslServerFactory EMPTY_SASL_SERVER_FACTORY = new SaslServerFactory() {
        public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
            return null;
        }

        public String[] getMechanismNames(final Map<String, ?> props) {
            return NO_STRINGS;
        }
    };

    /**
     * Get a SASL client factory which returns an Elytron-provided mechanism.
     *
     * @return the SASL client factory (not {@code null})
     */
    public static SaslClientFactory getElytronSaslClientFactory() {
        return new ServiceLoaderSaslClientFactory(SaslFactories.class.getClassLoader());
    }

    /**
     * Get a SASL server factory which returns an Elytron-provided mechanism.
     *
     * @return the SASL server factory (not {@code null})
     */
    public static SaslServerFactory getElytronSaslServerFactory() {
        return new ServiceLoaderSaslServerFactory(SaslFactories.class.getClassLoader());
    }

    /**
     * Get a SASL client factory which searches all the given class loaders in order for mechanisms.
     *
     * @param classLoaders the class loaders to search
     * @return the SASL client factory (not {@code null})
     */
    public static SaslClientFactory getSearchSaslClientFactory(ClassLoader... classLoaders) {
        Assert.checkNotNullParam("classLoaders", classLoaders);
        SaslClientFactory[] factories = new SaslClientFactory[classLoaders.length];
        for (int i = 0, classLoadersLength = classLoaders.length; i < classLoadersLength; i++) {
            factories[i] = new ServiceLoaderSaslClientFactory(classLoaders[i]);
        }
        return new AggregateSaslClientFactory(factories);
    }

    /**
     * Get a SASL server factory which searches all the given class loaders in order for mechanisms.
     *
     * @param classLoaders the class loaders to search
     * @return the SASL server factory (not {@code null})
     */
    public static SaslServerFactory getSearchSaslServerFactory(ClassLoader... classLoaders) {
        Assert.checkNotNullParam("classLoaders", classLoaders);
        SaslServerFactory[] factories = new SaslServerFactory[classLoaders.length];
        for (int i = 0, classLoadersLength = classLoaders.length; i < classLoadersLength; i++) {
            factories[i] = new ServiceLoaderSaslServerFactory(classLoaders[i]);
        }
        return new AggregateSaslServerFactory(factories);
    }

    /**
     * Get a SASL client factory which uses the currently installed security providers to locate mechanisms.
     *
     * @return the SASL client factory (not {@code null})
     */
    public static SecurityProviderSaslClientFactory getProviderSaslClientFactory() {
        return providerSaslClientFactory;
    }

    /**
     * Get a SASL server factory which uses the currently installed security providers to locate mechanisms.
     *
     * @return the SASL server factory (not {@code null})
     */
    public static SecurityProviderSaslServerFactory getProviderSaslServerFactory() {
        return providerSaslServerFactory;
    }

    /**
     * Get a {@link SaslClientFactory} which does not provide any mechanisms.
     */
    public static SaslClientFactory getEmptySaslClientFactory() {
        return EMPTY_SASL_CLIENT_FACTORY;
    }

    /**
     * Get a {@link SaslServerFactory} which does not provide any mechanisms.
     */
    public static SaslServerFactory getEmptySaslServerFactory() {
        return EMPTY_SASL_SERVER_FACTORY;
    }

    /**
     * Efficiently, recursively filter mechanisms by provider.  If the filter accepts all array elements, the original
     * array is returned unchanged.  If the filter accepts none of the array elements, an empty array is returned.
     *
     * @param orig the original mech array
     * @param idx the recursive read index (start from 0)
     * @param len the recursive write length (start from 0)
     * @param currentProvider the provider being tested
     * @param mechFilter the filter predicate
     * @return the filtered array
     */
    static String[] filterMechanismsByProvider(String[] orig, int idx, int len, final Provider currentProvider, final BiPredicate<String, Provider> mechFilter) {
        if (idx == orig.length) {
            // end of array
            if (len == 0) {
                // no mechs
                return NO_STRINGS;
            } else {
                return idx == len ? orig : new String[len];
            }
        } else if (mechFilter.test(orig[idx], currentProvider)) {
            // ok
            String[] filtered = filterMechanismsByProvider(orig, idx + 1, len + 1, currentProvider, mechFilter);
            if (orig != filtered) {
                // we made a copy; populate it
                filtered[len] = orig[idx];
            }
            return filtered;
        } else {
            // skip this element
            return filterMechanismsByProvider(orig, idx + 1, len, currentProvider, mechFilter);
        }
    }

    @SuppressWarnings("unchecked")
    static BiPredicate<String, Provider> getProviderFilterPredicate(final Map<String, ?> props) {
        final Object filterObj = props.get(PROVIDER_FILTER_KEY);
        final BiPredicate<String, Provider> mechFilter;
        if (filterObj instanceof BiPredicate) {
            mechFilter = (BiPredicate<String, Provider>) filterObj;
        } else {
            mechFilter = (s, provider) -> true;
        }
        return mechFilter;
    }
}
