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

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.wildfly.common.Assert;
import org.wildfly.security.OneTimeSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.login.SecurityIdentity;

/**
 * SSL factories and utilities.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SSLUtils {

    private SSLUtils() {}

    private static final String serviceType = SSLContext.class.getSimpleName();

    /**
     * The key used to store the authenticated {@link SecurityIdentity} onto the {@link SSLSession}.
     */
    public static final String SSL_SESSION_IDENTITY_KEY = "org.wildfly.security.ssl.identity";

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
        return SSLUtils::throwIt;
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
     * @param sslConfigurator the SSL configurator
     * @return the configured SSL context
     */
    public static SSLContext createConfiguredSslContext(SSLContext original, final SSLConfigurator sslConfigurator) {
        return new DelegatingSSLContext(new ConfiguredSSLContextSpi(original, sslConfigurator));
    }

    /**
     * Create a configured SSL context factory from an outside SSL context.  The returned factory will create new instances
     * for every call, so it might be necessary to wrap with a {@link OneTimeSecurityFactory} instance.
     *
     * @param originalFactory the original SSL context factory
     * @param sslConfigurator the SSL configurator
     * @return the configured SSL context
     */
    public static SecurityFactory<SSLContext> createConfiguredSslContextFactory(SecurityFactory<SSLContext> originalFactory, final SSLConfigurator sslConfigurator) {
        return () -> createConfiguredSslContext(originalFactory.create(), sslConfigurator);
    }

    private static final SecurityFactory<X509TrustManager> DEFAULT_TRUST_MANAGER_SECURITY_FACTORY = new OneTimeSecurityFactory<>(() -> {
        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);
        for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
            if (trustManager instanceof X509TrustManager) {
                return (X509TrustManager) trustManager;
            }
        }
        throw ElytronMessages.log.noDefaultTrustManager();
    });

    /**
     * Get the platform's default X.509 trust manager security factory.  The factory caches the instance.
     *
     * @return the security factory for the default trust manager
     */
    public static SecurityFactory<X509TrustManager> getDefaultX509TrustManagerSecurityFactory() {
        return DEFAULT_TRUST_MANAGER_SECURITY_FACTORY;
    }

    /**
     * Get a server SSL engine which dispatches to the appropriate SSL context based on the SNI information in the
     * SSL greeting.
     *
     * @param selector the context selector to use (cannot be {@code null})
     * @return the SSL engine (not {@code null})
     */
    public static SSLEngine createSNIDispatchingSSLEngine(SNIServerSSLContextSelector selector) {
        Assert.checkNotNullParam("selector", selector);
        return new SNIServerSSLEngine(selector);
    }

    /**
     * Get a factory which produces SSL engines which dispatch to the appropriate SSL context based on the SNI information
     * in the SSL greeting.
     *
     * @param selector the context selector to use (cannot be {@code null})
     * @return the SSL engine factory (not {@code null})
     */
    public static SecurityFactory<SSLEngine> createSNIDispatchingSSLEngineFactory(SNIServerSSLContextSelector selector) {
        Assert.checkNotNullParam("selector", selector);
        return () -> new SNIServerSSLEngine(selector);
    }
}
