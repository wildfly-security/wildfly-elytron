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

package org.wildfly.security.ssl;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;

import org.wildfly.security.OneTimeSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security._private.ElytronMessages;

/**
 * A factory for SSL contexts.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SSLFactories {

    private SSLFactories() {}

    private static final String serviceType = SSLContext.class.getSimpleName();

    /**
     * Create an SSL context factory which locates the best context by searching the preferred providers in order using
     * the rules established in the given protocol selector.  If there are no matches, a factory is returned which
     *
     * @param protocolSelector the protocol selector
     * @param providerSupplier the provider supplier
     * @return the SSL context factory
     */
    public static SecurityFactory<SSLContext> createSslContextFactory(ProtocolSelector protocolSelector, Supplier<Provider[]> providerSupplier) {
        Provider[] providers = providerSupplier.get();
        Map<String, Provider> preferredProviderByAlgorithm = new IdentityHashMap<>();

        // compile all the providers that support SSLContext.

        for (Provider provider : providers) {
            for (Provider.Service service : provider.getServices()) {
                if (serviceType.equals(service.getType())) {
                    String protocolName = service.getAlgorithm();
                    if (! preferredProviderByAlgorithm.containsKey(protocolName)) {
                        preferredProviderByAlgorithm.put(protocolName, provider);
                    }
                }
            }
        }

        // now figure out the supported protocol set.

        String[] supportedProtocols = protocolSelector.evaluate(preferredProviderByAlgorithm.keySet().toArray(new String[preferredProviderByAlgorithm.size()]));
        for (String supportedProtocol : supportedProtocols) {
            Provider provider = preferredProviderByAlgorithm.get(supportedProtocol);
            if (provider != null) {
                return createSimpleSslContextFactory(supportedProtocol, provider);
            }
        }
        return SSLFactories::throwIt;
    }

    private static SSLContext throwIt() throws NoSuchAlgorithmException {
        throw ElytronMessages.log.noAlgorithmForSslProtocol();
    }

    /**
     * Create a simple security factory for SSL contexts.
     *
     * @param protocol the protocol name
     * @param provider the provider to use
     * @return the SSL context factory
     */
    public static SecurityFactory<SSLContext> createSimpleSslContextFactory(String protocol, Provider provider) {
        return () -> SSLContext.getInstance(protocol, provider);
    }

    /**
     * Create a configured SSL context from an outside SSL context.
     *
     * @param original the original SSL context
     * @param protocolSelector the protocol selector to apply
     * @param cipherSuiteSelector the cipher suite selector to apply
     * @return the configured SSL context
     */
    public static SSLContext createConfiguredSslContext(SSLContext original, ProtocolSelector protocolSelector, CipherSuiteSelector cipherSuiteSelector) {
        return new DelegatingSSLContext(new ConfiguredSSLContextSpi(original, protocolSelector, cipherSuiteSelector));
    }

    /**
     * Create a configured SSL context factory from an outside SSL context.  The returned factory will create new instances
     * for every call, so it might be necessary to wrap with a {@link OneTimeSecurityFactory} instance.
     *
     * @param originalFactory the original SSL context factory
     * @param protocolSelector the protocol selector to apply
     * @param cipherSuiteSelector the cipher suite selector to apply
     * @return the configured SSL context
     */
    public static SecurityFactory<SSLContext> createConfiguredSslContextFactory(SecurityFactory<SSLContext> originalFactory, ProtocolSelector protocolSelector, CipherSuiteSelector cipherSuiteSelector) {
        return () -> createConfiguredSslContext(originalFactory.create(), protocolSelector, cipherSuiteSelector);
    }
}
