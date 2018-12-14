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

import java.net.IDN;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.wildfly.common.Assert;
import org.wildfly.security.OneTimeSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.server.SecurityIdentity;

import static org.wildfly.security.ssl.ElytronMessages.log;

/**
 * SSL factories and utilities.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SSLUtils {

    private static final String[] NO_STRINGS = new String[0];

    private SSLUtils() {}

    private static final String SERVICE_TYPE = SSLContext.class.getSimpleName();

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
        return createSslContextFactory(protocolSelector, providerSupplier, null);
    }

    /**
     * Create an SSL context factory which locates the best context by searching the preferred providers in order using
     * the rules established in the given protocol selector.  If there are no matches, a factory is returned which
     *
     * @param protocolSelector the protocol selector
     * @param providerSupplier the provider supplier
     * @param providerName the provider name to select, or {@code null} to allow any
     * @return the SSL context factory
     */
    public static SecurityFactory<SSLContext> createSslContextFactory(ProtocolSelector protocolSelector, Supplier<Provider[]> providerSupplier, String providerName) {
        final Map<String, List<Provider>> preferredProviderByAlgorithm = new IdentityHashMap<>();

        // compile all the providers that support SSLContext.

        for (Provider provider : providerSupplier.get()) {
            // if a provider name was given, filter by it
            if (providerName != null && ! providerName.equals(provider.getName())) {
                continue;
            }
            Set<Service> services = provider.getServices();
            if (services != null) {
                for (Provider.Service service : services) {
                    if (SERVICE_TYPE.equals(service.getType())) {
                        String protocolName = service.getAlgorithm();
                        List<Provider> providerList = preferredProviderByAlgorithm.computeIfAbsent(protocolName, s -> new ArrayList<>());
                        providerList.add(provider);

                        if (log.isTraceEnabled()) {
                            log.tracef("Provider %s was added for algorithm %s", provider, protocolName);
                        }
                    }
                }
            }
        }

        // now return a factory that will return the best match is can create.
        final String[] supportedProtocols = protocolSelector.evaluate(preferredProviderByAlgorithm.keySet().toArray(NO_STRINGS));
        if (log.isTraceEnabled()) {
            log.tracef("Supported protocols are: %s", Arrays.toString(supportedProtocols));
        }
        if (supportedProtocols.length > 0) {
            return () -> {
                for (String protocol : supportedProtocols) {
                    List<Provider> providerList = preferredProviderByAlgorithm.getOrDefault(protocol, Collections.emptyList());
                    if (log.isTraceEnabled()) {
                        if (providerList.isEmpty()) {
                            log.tracef("No providers are available for protocol %s", protocol);
                        }
                    }
                    for (Provider provider : providerList) {
                        try {
                            if (log.isTraceEnabled()) {
                                log.tracef("Attempting to get an SSLContext instance using protocol %s and provider %s", protocol, provider);
                            }
                            return SSLContext.getInstance(protocol, provider);
                        } catch (NoSuchAlgorithmException ignored) {
                            if (log.isTraceEnabled()) {
                                log.tracef(ignored, "Provider %s has no such protocol %s", provider, protocol);
                            }
                        }
                    }
                }

                if (log.isTraceEnabled()) {
                    log.tracef("No %s provided by providers in %s: %s", SERVICE_TYPE, SSLUtils.class.getSimpleName(), Arrays.toString(providerSupplier.get()));
                }

                throw ElytronMessages.log.noAlgorithmForSslProtocol();
            };
        }

        if (log.isTraceEnabled()) {
            log.tracef("No %s provided by providers in %s: %s", SERVICE_TYPE, SSLUtils.class.getSimpleName(), Arrays.toString(providerSupplier.get()));
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
        return createConfiguredSslContext(original, sslConfigurator, true);
    }

    /**
     * Create a configured SSL context from an outside SSL context.
     *
     * @param original the original SSL context
     * @param sslConfigurator the SSL configurator
     * @param wrap should the resulting SSLEngine, SSLSocket, and SSLServerSocket instances be wrapped using the configurator.
     * @return the configured SSL context
     */
    public static SSLContext createConfiguredSslContext(SSLContext original, final SSLConfigurator sslConfigurator, final boolean wrap) {
        return new DelegatingSSLContext(new ConfiguredSSLContextSpi(original, sslConfigurator, wrap));
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
     * Get a server SSL engine which dispatches to the appropriate SSL context based on the information in the
     * SSL greeting.
     *
     * @param selector the context selector to use (cannot be {@code null})
     * @return the SSL engine (not {@code null})
     */
    public static SSLEngine createSelectingSSLEngine(SSLContextSelector selector) {
        Assert.checkNotNullParam("selector", selector);
        return new SelectingServerSSLEngine(selector);
    }

    /**
     * Get a server SSL engine which dispatches to the appropriate SSL context based on the information in the
     * SSL greeting.
     *
     * @param selector the context selector to use (cannot be {@code null})
     * @param host the advisory host name
     * @param port the advisory port number
     * @return the SSL engine (not {@code null})
     */
    public static SSLEngine createSelectingSSLEngine(SSLContextSelector selector, String host, int port) {
        Assert.checkNotNullParam("selector", selector);
        return new SelectingServerSSLEngine(selector, host, port);
    }

    /**
     * Create an {@code SNIMatcher} which matches SNI host names that satisfy the given predicate.
     *
     * @param predicate the predicate (must not be {@code null})
     * @return the SNI matcher (not {@code null})
     */
    public static SNIMatcher createHostNamePredicateSNIMatcher(Predicate<SNIHostName> predicate) {
        Assert.checkNotNullParam("predicate", predicate);
        return new SNIMatcher(StandardConstants.SNI_HOST_NAME) {
            public boolean matches(final SNIServerName sniServerName) {
                return sniServerName instanceof SNIHostName && predicate.test((SNIHostName) sniServerName);
            }
        };
    }

    /**
     * Create an {@code SNIMatcher} which matches SNI host name strings that satisfy the given predicate.
     *
     * @param predicate the predicate (must not be {@code null})
     * @return the SNI matcher (not {@code null})
     * @see IDN
     */
    public static SNIMatcher createHostNameStringPredicateSNIMatcher(Predicate<String> predicate) {
        Assert.checkNotNullParam("predicate", predicate);
        return new SNIMatcher(StandardConstants.SNI_HOST_NAME) {
            public boolean matches(final SNIServerName sniServerName) {
                return sniServerName instanceof SNIHostName && predicate.test(((SNIHostName) sniServerName).getAsciiName());
            }
        };
    }

    /**
     * Create an {@code SNIMatcher} which matches SNI host names that are equal to the given (ASCII) string.
     *
     * @param string the host name string (must not be {@code null})
     * @return the SNI matcher (not {@code null})
     * @see IDN
     */
    public static SNIMatcher createHostNameStringSNIMatcher(String string) {
        Assert.checkNotNullParam("string", string);
        return createHostNameStringPredicateSNIMatcher(string::equals);
    }

    /**
     * Create an {@code SNIMatcher} which matches SNI host name strings which end with the given suffix.
     *
     * @param suffix the suffix to match (must not be {@code null} or empty)
     * @return the SNI matcher (not {@code null})
     */
    public static SNIMatcher createHostNameSuffixSNIMatcher(String suffix) {
        Assert.checkNotNullParam("suffix", suffix);
        Assert.checkNotEmptyParam("suffix", suffix);
        final String finalSuffix = suffix.startsWith(".") ? suffix : "." + suffix;
        return createHostNameStringPredicateSNIMatcher(n -> n.endsWith(finalSuffix));
    }

    /**
     * Get a factory which produces SSL engines which dispatch to the appropriate SSL context based on the information
     * in the SSL greeting.
     *
     * @param selector the context selector to use (cannot be {@code null})
     * @return the SSL engine factory (not {@code null})
     */
    public static SecurityFactory<SSLEngine> createDispatchingSSLEngineFactory(SSLContextSelector selector) {
        Assert.checkNotNullParam("selector", selector);
        return () -> new SelectingServerSSLEngine(selector);
    }

    /**
     * Get the value of the given key from the SSL session, or a default value if the key is not set.
     *
     * @param sslSession the SSL session (must not be {@code null})
     * @param key the key to retrieve (must not be {@code null})
     * @param defaultValue the value to return if the key is not present
     * @return the session value or the default value
     */
    public static Object getOrDefault(SSLSession sslSession, String key, Object defaultValue) {
        Assert.checkNotNullParam("sslSession", sslSession);
        Assert.checkNotNullParam("key", key);
        final Object value = sslSession.getValue(key);
        return value != null ? value : defaultValue;
    }

    /**
     * Put a value on the session if the value is not yet set.  This method is atomic with respect to other methods
     * on this class.
     *
     * @param sslSession the SSL session (must not be {@code null})
     * @param key the key to retrieve (must not be {@code null})
     * @param newValue the value to set (must not be {@code null})
     * @return the existing value, or {@code null} if the value was successfully set
     */
    public static Object putSessionValueIfAbsent(SSLSession sslSession, String key, Object newValue) {
        Assert.checkNotNullParam("sslSession", sslSession);
        Assert.checkNotNullParam("key", key);
        Assert.checkNotNullParam("newValue", newValue);
        synchronized (sslSession) {
            final Object existing = sslSession.getValue(key);
            if (existing == null) {
                sslSession.putValue(key, newValue);
                return null;
            } else {
                return existing;
            }
        }
    }

    /**
     * Remove and return a value on the session.  This method is atomic with respect to other methods on this class.
     *
     * @param sslSession the SSL session (must not be {@code null})
     * @param key the key to retrieve (must not be {@code null})
     * @return the existing value, or {@code null} if no such value was set
     */
    public static Object removeSessionValue(SSLSession sslSession, String key) {
        Assert.checkNotNullParam("sslSession", sslSession);
        Assert.checkNotNullParam("key", key);
        synchronized (sslSession) {
            final Object existing = sslSession.getValue(key);
            sslSession.removeValue(key);
            return existing;
        }
    }

    /**
     * Remove the given key-value pair on the session.  This method is atomic with respect to other methods on this class.
     *
     * @param sslSession the SSL session (must not be {@code null})
     * @param key the key to remove (must not be {@code null})
     * @param value the value to remove (must not be {@code null})
     * @return {@code true} if the key/value pair was removed, {@code false} if the key was not present or the value was not equal to the given value
     */
    public static boolean removeSessionValue(SSLSession sslSession, String key, Object value) {
        Assert.checkNotNullParam("sslSession", sslSession);
        Assert.checkNotNullParam("key", key);
        Assert.checkNotNullParam("value", value);
        synchronized (sslSession) {
            final Object existing = sslSession.getValue(key);
            if (Objects.equals(existing, value)) {
                sslSession.removeValue(key);
                return true;
            } else {
                return false;
            }
        }
    }

    /**
     * Replace the given key's value with a new value.  If there is no value for the given key, no action is performed.
     * This method is atomic with respect to other methods on this class.
     *
     * @param sslSession the SSL session (must not be {@code null})
     * @param key the key to retrieve (must not be {@code null})
     * @param newValue the value to set (must not be {@code null})
     * @return the existing value, or {@code null} if the value was not set
     */
    public static Object replaceSessionValue(SSLSession sslSession, String key, Object newValue) {
        Assert.checkNotNullParam("sslSession", sslSession);
        Assert.checkNotNullParam("key", key);
        Assert.checkNotNullParam("newValue", newValue);
        synchronized (sslSession) {
            final Object existing = sslSession.getValue(key);
            if (existing != null) sslSession.putValue(key, newValue);
            return existing;
        }
    }

    /**
     * Replace the given key's value with a new value if (and only if) it is mapped to the given existing value.
     * This method is atomic with respect to other methods on this class.
     *
     * @param sslSession the SSL session (must not be {@code null})
     * @param key the key to retrieve (must not be {@code null})
     * @param oldValue the value to match (must not be {@code null})
     * @param newValue the value to set (must not be {@code null})
     * @return {@code true} if the value was matched and replaced, or {@code false} if the value did not match and no action was taken
     */
    public static boolean replaceSessionValue(SSLSession sslSession, String key, Object oldValue, Object newValue) {
        Assert.checkNotNullParam("sslSession", sslSession);
        Assert.checkNotNullParam("key", key);
        Assert.checkNotNullParam("oldValue", oldValue);
        Assert.checkNotNullParam("newValue", newValue);
        synchronized (sslSession) {
            final Object existing = sslSession.getValue(key);
            if (Objects.equals(existing, oldValue)) {
                sslSession.putValue(key, newValue);
                return true;
            } else {
                return false;
            }
        }
    }

    /**
     * Get or compute the value for the given key, storing the computed value (if one is generated).  The function
     * must not generate a {@code null} value or an unspecified exception will result.
     *
     * @param sslSession the SSL session (must not be {@code null})
     * @param key the key to retrieve (must not be {@code null})
     * @param mappingFunction the function to apply to acquire the value (must not be {@code null})
     * @return the stored or new value (not {@code null})
     */
    public static <R> R computeIfAbsent(SSLSession sslSession, String key, Function<String, R> mappingFunction) {
        Assert.checkNotNullParam("sslSession", sslSession);
        Assert.checkNotNullParam("key", key);
        Assert.checkNotNullParam("mappingFunction", mappingFunction);
        synchronized (sslSession) {
            final R existing = (R) sslSession.getValue(key);
            if (existing == null) {
                R newValue = mappingFunction.apply(key);
                Assert.assertNotNull(newValue);
                sslSession.putValue(key, newValue);
                return newValue;
            } else {
                return existing;
            }
        }
    }
}
