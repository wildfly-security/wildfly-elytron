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

package org.wildfly.security.ssl;

import static org.wildfly.security.provider.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.security.Provider;
import java.security.Security;
import java.util.function.Supplier;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.wildfly.common.Assert;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.OneTimeSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;

/**
 * A class which allows building and configuration of a single client- or server-side SSL context.  The builder requires, at a
 * minimum, that a key manager be set; all other parameters have default values as follows:
 * <ul>
 *     <li>The security domain defaults to being empty (no client authentication possible)</li>
 *     <li>The principal decoder defaults to the {@linkplain PrincipalDecoder#DEFAULT default principal decoder}</li>
 *     <li>The cipher suite selector defaults to {@link CipherSuiteSelector#openSslCombinedDefault()}</li>
 *     <li>The protocol suite selector defaults to {@link ProtocolSelector#DEFAULT_SELECTOR}</li>
 *     <li>The "require client authentication" flag defaults to {@code false}</li>
 *     <li>The provider supplier defaults to {@link Security#getProviders() Security::getProviders}</li>
 * </ul>
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SSLContextBuilder {

    private SecurityDomain securityDomain;
    private CipherSuiteSelector cipherSuiteSelector = CipherSuiteSelector.openSslCombinedDefault();
    private ProtocolSelector protocolSelector = ProtocolSelector.DEFAULT_SELECTOR;
    private boolean useCipherSuitesOrder = true;
    private boolean wantClientAuth;
    private boolean needClientAuth;
    private boolean authenticationOptional;
    private boolean clientMode;
    private int sessionCacheSize;
    private int sessionTimeout;
    private SecurityFactory<X509ExtendedKeyManager> keyManagerSecurityFactory;
    private SecurityFactory<X509TrustManager> trustManagerSecurityFactory = SSLUtils.getDefaultX509TrustManagerSecurityFactory();
    private Supplier<Provider[]> providerSupplier = INSTALLED_PROVIDERS;
    private String providerName;
    private boolean wrap = true;
    private MechanismConfigurationSelector mechanismConfigurationSelector;

    /**
     * Set the security domain to use to authenticate clients.
     *
     * @param securityDomain the security domain to use to authenticate clients, or {@code null} to disable client
     *    certificate authentication
     */
    public SSLContextBuilder setSecurityDomain(final SecurityDomain securityDomain) {

        if (securityDomain != null && securityDomain.getEvidenceVerifySupport(X509PeerCertificateChainEvidence.class).isNotSupported()) {
            throw ElytronMessages.tls.securityDomainOfSSLContextDoesNotSupportX509();
        }

        this.securityDomain = securityDomain;

        return this;
    }

    /**
     * Set the cipher suite selector to use for this context.
     *
     * @param cipherSuiteSelector the cipher suite selector (not {@code null})
     */
    public SSLContextBuilder setCipherSuiteSelector(final CipherSuiteSelector cipherSuiteSelector) {
        Assert.checkNotNullParam("cipherSuiteSelector", cipherSuiteSelector);
        this.cipherSuiteSelector = cipherSuiteSelector;

        return this;
    }

    /**
     * Set the protocol selector to use for this context.
     *
     * @param protocolSelector the protocol selector to use for this context (not {@code null})
     */
    public SSLContextBuilder setProtocolSelector(final ProtocolSelector protocolSelector) {
        Assert.checkNotNullParam("protocolSelector", protocolSelector);
        this.protocolSelector = protocolSelector;

        return this;
    }

    /**
     * Sets whether the local cipher suites preference should be honored.
     *
     * @param useCipherSuitesOrder whether the local cipher suites preference should be honored.
     */
    public SSLContextBuilder setUseCipherSuitesOrder(final boolean useCipherSuitesOrder) {
        Assert.checkNotNullParam("useCipherSuitesOrder", useCipherSuitesOrder);
        this.useCipherSuitesOrder = useCipherSuitesOrder;

        return this;
    }

    /**
     * Force the SSLContext created by this builder to want client authentication.
     *
     * The SSLContext returned by this builder will be configured to want client authentication if this value is set to true OR
     * of a SecurityDomain is associated.
     *
     * @param wantClientAuth should the SSLContext be forced to want client authentication.
     */
    public SSLContextBuilder setWantClientAuth(final boolean wantClientAuth) {
        this.wantClientAuth = wantClientAuth;

        return this;
    }

    /**
     * Force the SSLContext created by this builder to need client authentication.
     *
     * The SSLContext returned by this builder will be configured to need client authentication if this value is set to true.
     *
     * @param needClientAuth should the SSLContext be forced to need client authentication.
     */
    public SSLContextBuilder setNeedClientAuth(final boolean needClientAuth) {
        this.needClientAuth = needClientAuth;

        return this;
    }

    /**
     * Where a SecurityDomain is associated with this Builder if the client presents a certificate an attempt will be made to
     * obtain a SecurityIdentity by using the certificate for authentication, setting this flag to {@code true} allows for a
     * failed authentication to be silently ignored.
     *
     * This setting does not bypass any certificate checking performed by the underlying TrustManager so failure there will still cause the connection attempt to be aborted.
     *
     * The reason this setting would be used would be to enable a fallback to another authentication mechanism after the connection is established.
     *
     * Note: Where this is no security domain associated there is no authentication step so this value will be ignored.
     *
     * @param authenticationOptional should the authentication step be allowed to silently fail.
     */
    public SSLContextBuilder setAuthenticationOptional(final boolean authenticationOptional) {
        this.authenticationOptional = authenticationOptional;

        return this;
    }


    /**
     * Sets the size of the cache used for storing SSLSession objects.
     *
     * @param sessionCacheSize the size of the cache used for storing SSLSession objects.
     * @return The {@link SSLContextBuilder} to allow chaining of method calls.
     */
    public SSLContextBuilder setSessionCacheSize(final int sessionCacheSize) {
        this.sessionCacheSize = sessionCacheSize;

        return this;
    }

    /**
     * Sets the timeout limit for SSLSession objects.
     *
     * @param sessionTimeout the timeout limit for SSLSession objects.
     * @return The {@link SSLContextBuilder} to allow chaining of method calls.
     */
    public SSLContextBuilder setSessionTimeout(final int sessionTimeout) {
        this.sessionTimeout = sessionTimeout;

        return this;
    }

    /**
     * Set the factory for the key manager which should be used to hold identities for this context.
     *
     * @param keyManagerSecurityFactory the security factory which produces the key manager (not {@code null})
     */
    public SSLContextBuilder setKeyManagerSecurityFactory(final SecurityFactory<X509ExtendedKeyManager> keyManagerSecurityFactory) {
        Assert.checkNotNullParam("keyManagerSecurityFactory", keyManagerSecurityFactory);
        this.keyManagerSecurityFactory = keyManagerSecurityFactory;

        return this;
    }

    /**
     * Set the key manager which should be used to hold identities for this context.
     *
     * @param keyManager the security factory which produces the key manager (not {@code null})
     */
    public SSLContextBuilder setKeyManager(final X509ExtendedKeyManager keyManager) {
        Assert.checkNotNullParam("keyManager", keyManager);
        this.keyManagerSecurityFactory = new FixedSecurityFactory<>(keyManager);

        return this;
    }

    /**
     * Set the factory for the trust manager which should be used for the initial trust decisions during connection.
     *
     * @param trustManagerSecurityFactory the factory for the trust manager which should be used for the initial trust decisions during connection (not {@code null}).
     */
    public SSLContextBuilder setTrustManagerSecurityFactory(final SecurityFactory<X509TrustManager> trustManagerSecurityFactory) {
        this.trustManagerSecurityFactory = Assert.checkNotNullParam("trustManagerSecurityFactory", trustManagerSecurityFactory);

        return this;
    }

    /**
     * Set the trust manager which should be used to hold identities for this context.
     *
     * @param trustManager the trust manager which should be used to hold identities for this context (not {@code null}).
     */
    public SSLContextBuilder setTrustManager(final X509TrustManager trustManager) {
        Assert.checkNotNullParam("trustManager", trustManager);
        this.trustManagerSecurityFactory = new FixedSecurityFactory<>(trustManager);

        return this;
    }

    // todo: add a setter which simply accepts a single org.wildfly.security.ssl.X500CertificateChainPrivateCredential instance

    /**
     * Set the provider supplier.
     *
     * @param providerSupplier the provider supplier (not {@code null})
     */
    public SSLContextBuilder setProviderSupplier(final Supplier<Provider[]> providerSupplier) {
        Assert.checkNotNullParam("providerSupplier", providerSupplier);
        this.providerSupplier = providerSupplier;

        return this;
    }

    /**
     * Set the provider name.
     *
     * @param name the provider name (if {@code null} and provider is allowed)
     * @return this builder
     */
    public SSLContextBuilder setProviderName(final String name) {
        this.providerName = name;
        return this;
    }

    /**
     * Set the client mode of the target SSL context.
     *
     * @param clientMode {@code true} to use client mode, {@code false} otherwise
     * @return this builder
     */
    public SSLContextBuilder setClientMode(final boolean clientMode) {
        this.clientMode = clientMode;
        return this;
    }

    /**
     * Set if the configured SSL engine and sockets created using the SSL context should be wrapped to prevent modification to the configuration.
     *
     * Defaults to {@code true}.
     *
     * @param wrap should the engine or socket created by the SSL context be wrapped to prevent modification to the configuration.
     * @return this builder
     */
    public SSLContextBuilder setWrap(final boolean wrap) {
        this.wrap = wrap;
        return this;
    }

    /**
     * Set selector of mechanism configuration for {@link ServerAuthenticationContext}, which will be used for SSL client authentication.
     *
     * @param mechanismConfigurationSelector mechanism configuration selector to be used by {@link ServerAuthenticationContext} in SSL authentication.
     * @return this builder
     */
    public SSLContextBuilder setMechanismConfigurationSelector(final MechanismConfigurationSelector mechanismConfigurationSelector) {
        this.mechanismConfigurationSelector = mechanismConfigurationSelector;
        return this;
    }



    /**
     * Build a security factory for the new context.  The factory will cache the constructed instance.
     *
     * @return the security factory
     */
    public SecurityFactory<SSLContext> build() {
        final SecurityDomain securityDomain = this.securityDomain;
        final CipherSuiteSelector cipherSuiteSelector = this.cipherSuiteSelector;
        final ProtocolSelector protocolSelector = this.protocolSelector;
        final SecurityFactory<X509TrustManager> trustManagerSecurityFactory = this.trustManagerSecurityFactory;
        final SecurityFactory<X509ExtendedKeyManager> keyManagerSecurityFactory = this.keyManagerSecurityFactory;
        final Supplier<Provider[]> providerSupplier = this.providerSupplier;
        final boolean clientMode = this.clientMode;
        final boolean authenticationOptional = this.authenticationOptional;
        final int sessionCacheSize = this.sessionCacheSize;
        final int sessionTimeout = this.sessionTimeout;
        final boolean wantClientAuth = this.wantClientAuth;
        final boolean needClientAuth = this.needClientAuth;
        final boolean useCipherSuitesOrder = this.useCipherSuitesOrder;
        final boolean wrap  = this.wrap;
        final MechanismConfigurationSelector mechanismConfigurationSelector = this.mechanismConfigurationSelector != null ?
                this.mechanismConfigurationSelector :
                MechanismConfigurationSelector.constantSelector(MechanismConfiguration.EMPTY);

        return new OneTimeSecurityFactory<>(() -> {
            final SecurityFactory<SSLContext> sslContextFactory = SSLUtils.createSslContextFactory(protocolSelector, providerSupplier, providerName);
            // construct the original context
            final SSLContext sslContext = sslContextFactory.create();
            SSLSessionContext sessionContext = clientMode ? sslContext.getClientSessionContext() : sslContext.getServerSessionContext();
            if (sessionContext != null) {
                if (sessionCacheSize >= 0) sessionContext.setSessionCacheSize(sessionCacheSize);
                if (sessionTimeout >= 0) sessionContext.setSessionTimeout(sessionTimeout);
            }
            final X509KeyManager x509KeyManager = keyManagerSecurityFactory == null ? null : keyManagerSecurityFactory.create();
            final X509TrustManager x509TrustManager = trustManagerSecurityFactory.create();
            final boolean canAuthPeers = securityDomain != null && securityDomain.getEvidenceVerifySupport(X509PeerCertificateChainEvidence.class).mayBeSupported();

            if (ElytronMessages.tls.isTraceEnabled()) {
                ElytronMessages.tls.tracef("SSLContext initialization:%n" +
                                "    securityDomain = %s%n" +
                                "    canAuthPeers = %s%n" +
                                "    cipherSuiteSelector = %s%n" +
                                "    protocolSelector = %s%n" +
                                "    x509TrustManager = %s%n" +
                                "    x509KeyManager = %s%n" +
                                "    providerSupplier = %s%n" +
                                "    clientMode = %s%n" +
                                "    authenticationOptional = %s%n" +
                                "    sessionCacheSize = %s%n" +
                                "    sessionTimeout = %s%n" +
                                "    wantClientAuth = %s%n" +
                                "    needClientAuth = %s%n" +
                                "    useCipherSuitesOrder = %s%n" +
                                "    wrap = %s%n",
                        securityDomain, canAuthPeers, cipherSuiteSelector, protocolSelector, x509TrustManager,
                        x509KeyManager, providerSupplier, clientMode, authenticationOptional, sessionCacheSize,
                        sessionTimeout, wantClientAuth, needClientAuth, useCipherSuitesOrder, wrap);
            }

            sslContext.init(x509KeyManager == null ? null : new KeyManager[]{
                    x509KeyManager
            }, new TrustManager[]{
                    canAuthPeers ?
                            new SecurityDomainTrustManager(x509TrustManager, securityDomain, authenticationOptional, mechanismConfigurationSelector) :
                            x509TrustManager
            }, null);

            // now, set up the wrapping configuration
            final SSLConfigurator sslConfigurator = clientMode ?
                    new SSLConfiguratorImpl(protocolSelector, cipherSuiteSelector, useCipherSuitesOrder) :
                    new SSLConfiguratorImpl(protocolSelector, cipherSuiteSelector, wantClientAuth || canAuthPeers, needClientAuth, useCipherSuitesOrder);
            final ConfiguredSSLContextSpi contextSpi = new ConfiguredSSLContextSpi(sslContext, sslConfigurator, wrap);
            return new DelegatingSSLContext(contextSpi);
        });
    }
}
