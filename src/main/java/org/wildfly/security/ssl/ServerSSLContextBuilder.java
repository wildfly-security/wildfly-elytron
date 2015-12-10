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

import java.security.Provider;
import java.security.Security;
import java.util.function.Supplier;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import org.wildfly.common.Assert;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.OneTimeSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.server.EvidenceDecoder;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.x500.X509CertificateEvidenceDecoder;

/**
 * A class which allows building and configuration of a single server-side SSL context.  The builder requires, at a
 * minimum, that a key manager be set; all other parameters have default values as follows:
 * <ul>
 *     <li>The security domain defaults to being empty (no client authentication possible)</li>
 *     <li>The evidence decoder defaults to the {@linkplain X509CertificateEvidenceDecoder X.509 decoder}</li>
 *     <li>The principal decoder defaults to the {@linkplain PrincipalDecoder#DEFAULT default principal decoder}</li>
 *     <li>The cipher suite selector defaults to {@link CipherSuiteSelector#openSslDefault()}</li>
 *     <li>The protocol suite selector defaults to {@link ProtocolSelector#DEFAULT_SELECTOR}</li>
 *     <li>The "require client authentication" flag defaults to {@code false}</li>
 *     <li>The provider supplier defaults to {@link Security#getProviders() Security::getProviders}</li>
 * </ul>
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ServerSSLContextBuilder {
    private SecurityDomain securityDomain;
    private EvidenceDecoder evidenceDecoder = X509CertificateEvidenceDecoder.getInstance();
    private CipherSuiteSelector cipherSuiteSelector = CipherSuiteSelector.openSslDefault();
    private ProtocolSelector protocolSelector = ProtocolSelector.DEFAULT_SELECTOR;
    private boolean requireClientAuth;
    private SecurityFactory<X509ExtendedKeyManager> keyManagerSecurityFactory;
    private Supplier<Provider[]> providerSupplier = Security::getProviders;

    /**
     * Set the security domain to use to authenticate clients.
     *
     * @param securityDomain the security domain to use to authenticate clients, or {@code null} to disable client
     *    certificate authentication
     */
    public void setSecurityDomain(final SecurityDomain securityDomain) {
        this.securityDomain = securityDomain;
    }

    /**
     * Set the evidence decoder.  This is the decoder used to get the principal from the client certificate.
     *
     * @param evidenceDecoder the evidence decoder
     */
    public void setEvidenceDecoder(final EvidenceDecoder evidenceDecoder) {
        Assert.checkNotNullParam("evidenceDecoder", evidenceDecoder);
        this.evidenceDecoder = evidenceDecoder;
    }

    /**
     * Set the cipher suite selector to use for this context.
     *
     * @param cipherSuiteSelector the cipher suite selector (not {@code null})
     */
    public void setCipherSuiteSelector(final CipherSuiteSelector cipherSuiteSelector) {
        Assert.checkNotNullParam("cipherSuiteSelector", cipherSuiteSelector);
        this.cipherSuiteSelector = cipherSuiteSelector;
    }

    /**
     * Set the protocol selector to use for this context.
     *
     * @param protocolSelector the protocol selector to use for this context (not {@code null})
     */
    public void setProtocolSelector(final ProtocolSelector protocolSelector) {
        Assert.checkNotNullParam("protocolSelector", protocolSelector);
        this.protocolSelector = protocolSelector;
    }

    /**
     * Set the client require-authentication flag.
     *
     * @param requireClientAuth {@code true} to require client authentication, {@code false} otherwise
     */
    public void setRequireClientAuth(final boolean requireClientAuth) {
        this.requireClientAuth = requireClientAuth;
    }

    /**
     * Set the factory for the key manager which should be used to hold identities for this context.
     *
     * @param keyManagerSecurityFactory the security factory which produces the key manager (not {@code null})
     */
    public void setKeyManagerSecurityFactory(final SecurityFactory<X509ExtendedKeyManager> keyManagerSecurityFactory) {
        Assert.checkNotNullParam("keyManagerSecurityFactory", keyManagerSecurityFactory);
        this.keyManagerSecurityFactory = keyManagerSecurityFactory;
    }

    /**
     * Set the key manager which should be used to hold identities for this context.
     *
     * @param keyManager the security factory which produces the key manager (not {@code null})
     */
    public void setKeyManager(final X509ExtendedKeyManager keyManager) {
        Assert.checkNotNullParam("keyManager", keyManager);
        this.keyManagerSecurityFactory = new FixedSecurityFactory<>(keyManager);
    }

    // todo: add a setter which simply accepts a single org.wildfly.security.ssl.X500CertificateChainPrivateCredential instance

    /**
     * Set the provider supplier.
     *
     * @param providerSupplier the provider supplier (not {@code null})
     */
    public void setProviderSupplier(final Supplier<Provider[]> providerSupplier) {
        Assert.checkNotNullParam("providerSupplier", providerSupplier);
        this.providerSupplier = providerSupplier;
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
        final boolean requireClientAuth = this.requireClientAuth;
        final SecurityFactory<X509ExtendedKeyManager> keyManagerSecurityFactory = this.keyManagerSecurityFactory;
        final EvidenceDecoder evidenceDecoder = this.evidenceDecoder;
        final Supplier<Provider[]> providerSupplier = this.providerSupplier;
        return new OneTimeSecurityFactory<SSLContext>(() -> {
            final SecurityFactory<SSLContext> sslContextFactory = SSLUtils.createSslContextFactory(protocolSelector, providerSupplier);
            // construct the original context
            final SSLContext sslContext = sslContextFactory.create();
            final X509TrustManager x509TrustManager = SSLUtils.getDefaultX509TrustManagerSecurityFactory().create();
            final boolean canAuthClients = securityDomain != null;
            sslContext.init(new KeyManager[] {
                keyManagerSecurityFactory.create()
            }, new TrustManager[] {
                canAuthClients ?
                    new SecurityDomainTrustManager(x509TrustManager, securityDomain, evidenceDecoder) :
                    x509TrustManager
            }, null);
            // now, set up the wrapping configuration
            final SSLConfigurator sslConfigurator = new ServerSSLConfigurator(protocolSelector, cipherSuiteSelector, canAuthClients, canAuthClients && requireClientAuth);
            final ConfiguredSSLContextSpi contextSpi = new ConfiguredSSLContextSpi(sslContext, sslConfigurator);
            return new DelegatingSSLContext(contextSpi);
        });
    }
}
