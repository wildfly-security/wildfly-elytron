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

package org.wildfly.security.sasl.util;

import java.security.Provider;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiPredicate;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

/**
 * A SASL server factory which filters mechanisms based on the combination of mechanism name and security provider.
 * Mechanisms which do not come from a security provider are not filtered.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class MechanismProviderFilteringSaslServerFactory extends AbstractDelegatingSaslServerFactory {
    private final BiPredicate<String, Provider> predicate;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate factory
     * @param predicate the predicate to execute
     */
    public MechanismProviderFilteringSaslServerFactory(final SaslServerFactory delegate, final BiPredicate<String, Provider> predicate) {
        super(delegate);
        this.predicate = predicate;
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        BiPredicate<String, Provider> existing = SaslFactories.getProviderFilterPredicate(props);
        final HashMap<String, Object> newProps = new HashMap<String, Object>(props);
        if (existing != null) {
            newProps.put(SaslFactories.PROVIDER_FILTER_KEY, predicate.and(existing));
        } else {
            newProps.put(SaslFactories.PROVIDER_FILTER_KEY, predicate);
        }
        return super.createSaslServer(mechanism, protocol, serverName, newProps, cbh);
    }
}
