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

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.security.sasl.SaslException;

/**
 * A {@link SaslServerFactory} which uses the currently installed security providers to acquire a delegate
 * {@code SaslServerFactory}.  The provider service instances may or may not be cached.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SecurityProviderSaslServerFactory implements SaslServerFactory {

    private static final String serviceType = SaslServerFactory.class.getSimpleName();

    private final Supplier<Provider[]> providerSupplier;

    /**
     * Construct a new instance.
     *
     * @param providerSupplier the provider supplier
     */
    public SecurityProviderSaslServerFactory(final Supplier<Provider[]> providerSupplier) {
        this.providerSupplier = providerSupplier;
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        SaslServer saslServer;
        for (Provider currentProvider : providerSupplier.get()) {
            for (Provider.Service service : currentProvider.getServices()) {
                if (serviceType.equals(service.getType())) {
                    try {
                        saslServer = ((SaslServerFactory) service.newInstance(null)).createSaslServer(mechanism, protocol, serverName, props, cbh);
                        if (saslServer != null) {
                            return saslServer;
                        }
                    } catch (NoSuchAlgorithmException | ClassCastException | InvalidParameterException ignored) {
                    }
                }
            }
        }
        return null;
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        final Set<String> names = new LinkedHashSet<>();
        for (Provider currentProvider : providerSupplier.get()) {
            for (Provider.Service service : currentProvider.getServices()) {
                if (serviceType.equals(service.getType())) {
                    try {
                        Collections.addAll(names, ((SaslServerFactory) service.newInstance(null)).getMechanismNames(props));
                    } catch (NoSuchAlgorithmException | ClassCastException | InvalidParameterException ignored) {
                    }
                }
            }
        }
        return names.toArray(new String[names.size()]);
    }
}
