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

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

/**
 * A utility class for discovering SASL client and server factories.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SaslFactories {

    private SaslFactories() {
    }

    private static final SecurityProviderSaslClientFactory providerSaslClientFactory = new SecurityProviderSaslClientFactory();
    private static final SecurityProviderSaslServerFactory providerSaslServerFactory = new SecurityProviderSaslServerFactory();

    /**
     * Get a standard SASL client factory which uses extended callbacks and searches both installed providers as well as
     * {@code ServiceLoader}-style factories.
     *
     * @param classLoader the class loader from which to search
     * @return the SASL client factory
     */
    public static SaslClientFactory getStandardSaslClientFactory(ClassLoader classLoader) {
        return new AuthenticationCompleteCallbackSaslClientFactory(new AggregateSaslClientFactory(
            new ServiceLoaderSaslClientFactory(classLoader),
            providerSaslClientFactory
        ));
    }

    /**
     * Get a standard SASL server factory which uses extended callbacks and searches both installed providers as well as
     * {@code ServiceLoader}-style factories.
     *
     * @param classLoader the class loader from which to search
     * @return the SASL server factory
     */
    public static SaslServerFactory getStandardSaslServerFactory(ClassLoader classLoader) {
        return new AuthenticationCompleteCallbackSaslServerFactory(new AggregateSaslServerFactory(
            new ServiceLoaderSaslServerFactory(classLoader),
            providerSaslServerFactory
        ));
    }

    private static final String[] NO_STRINGS = new String[0];

    /**
     * A {@link SaslClientFactory} which does not provide any mechanisms.
     */
    public static final SaslClientFactory EMPTY_SASL_CLIENT_FACTORY = new SaslClientFactory() {
        public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
            return null;
        }

        public String[] getMechanismNames(final Map<String, ?> props) {
            return NO_STRINGS;
        }
    };

    /**
     * A {@link SaslServerFactory} which does not provide any mechanisms.
     */
    public static final SaslServerFactory EMPTY_SASL_SERVER_FACTORY = new SaslServerFactory() {
        public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
            return null;
        }

        public String[] getMechanismNames(final Map<String, ?> props) {
            return NO_STRINGS;
        }
    };
}
