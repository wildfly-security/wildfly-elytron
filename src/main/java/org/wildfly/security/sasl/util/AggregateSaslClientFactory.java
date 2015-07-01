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

import static org.wildfly.security._private.ElytronMessages.log;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

/**
 * A {@link SaslClientFactory} which aggregates other {@code SaslClientFactory} instances into one.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AggregateSaslClientFactory implements SaslClientFactory {
    private final SaslClientFactory[] factories;

    /**
     * Construct a new instance.
     *
     * @param factories the factories to aggregate (must not be {@code null})
     */
    public AggregateSaslClientFactory(final SaslClientFactory... factories) {
        if (factories == null) {
            throw log.nullParameter("factories");
        }
        this.factories = factories.clone();
    }

    /**
     * Construct a new instance.
     *
     * @param factories the factories to aggregate (must not be {@code null})
     */
    public AggregateSaslClientFactory(final Collection<SaslClientFactory> factories) {
        if (factories == null) {
            throw log.nullParameter("factories");
        }
        this.factories = factories.toArray(new SaslClientFactory[factories.size()]);
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        for (SaslClientFactory factory : factories) {
            if (factory != null) {
                final SaslClient saslClient = factory.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, cbh);
                if (saslClient != null) {
                    return saslClient;
                }
            }
        }
        return null;
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        final LinkedHashSet<String> names = new LinkedHashSet<String>();
        for (SaslClientFactory factory : factories) {
            Collections.addAll(names, factory.getMechanismNames(props));
        }
        return names.toArray(new String[names.size()]);
    }
}
