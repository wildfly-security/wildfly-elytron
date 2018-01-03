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

import static org.wildfly.security.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Supplier;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.security.sasl.SaslException;

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * A {@link SaslServerFactory} which uses the currently installed security providers to acquire a delegate
 * {@code SaslServerFactory}.  The provider service instances may or may not be cached.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SecurityProviderSaslServerFactory implements SaslServerFactory {

    private static final String SERVICE_TYPE = SaslServerFactory.class.getSimpleName();

    private final Supplier<Provider[]> providerSupplier;

    /**
     * Construct a new instance.
     *
     * @param providerSupplier the provider supplier
     */
    public SecurityProviderSaslServerFactory(final Supplier<Provider[]> providerSupplier) {
        this.providerSupplier = providerSupplier;
    }

    /**
     * Construct a new instance.  The currently installed system providers are used.
     */
    public SecurityProviderSaslServerFactory() {
        this(INSTALLED_PROVIDERS);
    }

    @Override
    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final BiPredicate<String, Provider> mechFilter = SaslFactories.getProviderFilterPredicate(props);
        SaslServer saslServer;
        for (Provider currentProvider : providerSupplier.get()) {
            if (currentProvider == null) {
                continue;
            }
            if (mechFilter.test(mechanism, currentProvider)) {
                Set<Service> services = currentProvider.getServices();
                if (services != null) {
                    for (Provider.Service service : services) {
                        if (SERVICE_TYPE.equals(service.getType())) {
                            try {
                                saslServer = ((SaslServerFactory) service.newInstance(null)).createSaslServer(mechanism,
                                        protocol, serverName, props, cbh);
                                if (saslServer != null) {
                                    if (log.isTraceEnabled()) {
                                        log.tracef("Creating SaslServer [%s] for mechanism [%s] and protocol [%s]", saslServer, mechanism, protocol);
                                    }
                                    return saslServer;
                                }
                            } catch (NoSuchAlgorithmException | ClassCastException | InvalidParameterException e) {
                                log.debug("Unable to create instance of SaslServerFactory", e);
                            }
                        }
                    }
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.tracef("No %s provided by provider supplier in %s: %s", SERVICE_TYPE, getClass().getSimpleName(), Arrays.toString(providerSupplier.get()));
        }
        return null;
    }

    @Override
    public String[] getMechanismNames(final Map<String, ?> props) {
        final BiPredicate<String, Provider> mechFilter = SaslFactories.getProviderFilterPredicate(props);
        final Set<String> names = new LinkedHashSet<>();
        for (Provider currentProvider : providerSupplier.get()) {
            Set<Service> services = currentProvider.getServices();
            if (services != null) {
                for (Service service : services) {
                    if (SERVICE_TYPE.equals(service.getType())) {
                        try {
                            final String[] mechanismNames = ((SaslServerFactory) service.newInstance(null)).getMechanismNames(props);
                            Collections.addAll(names, SaslFactories.filterMechanismsByProvider(mechanismNames, 0, 0, currentProvider, mechFilter));
                        } catch (NoSuchAlgorithmException | ClassCastException | InvalidParameterException e) {
                            log.debug("Unable to create instance", e);
                        }
                    }
                }
            }
        }
        if (names.size() == 0 && log.isTraceEnabled()) {
            log.tracef("No %s provided by provider supplier in %s: %s", SERVICE_TYPE, getClass().getSimpleName(), Arrays.toString(providerSupplier.get()));
        }
        return names.toArray(new String[names.size()]);
    }
}
