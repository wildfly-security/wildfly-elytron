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
import java.security.Security;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

/**
 * A {@link SaslClientFactory} which uses the currently installed security providers to acquire a delegate
 * {@code SaslClientFactory}.  The provider service instances may or may not be cached.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SecurityProviderSaslClientFactory implements SaslClientFactory {

    private static final String serviceType = SaslClientFactory.class.getSimpleName();

    /**
     * Construct a new instance.
     */
    public SecurityProviderSaslClientFactory() {
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        SaslClient saslClient;
        for (Provider currentProvider : Security.getProviders()) {
            for (Provider.Service service : currentProvider.getServices()) {
                if (serviceType.equals(service.getType())) {
                    try {
                        saslClient = ((SaslClientFactory) service.newInstance(null)).createSaslClient(mechanisms, authorizationId, protocol, serverName, props, cbh);
                        if (saslClient != null) {
                            return saslClient;
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
        for (Provider currentProvider : Security.getProviders()) {
            for (Provider.Service service : currentProvider.getServices()) {
                if (serviceType.equals(service.getType())) {
                    try {
                        Collections.addAll(names, ((SaslClientFactory) service.newInstance(null)).getMechanismNames(props));
                    } catch (NoSuchAlgorithmException | ClassCastException | InvalidParameterException ignored) {
                    }
                }
            }
        }
        return names.toArray(new String[names.size()]);
    }
}
