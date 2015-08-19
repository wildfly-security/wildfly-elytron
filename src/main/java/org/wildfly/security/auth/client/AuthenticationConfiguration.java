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

package org.wildfly.security.auth.client;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.function.Supplier;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.ietf.jgss.GSSCredential;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.ssl.CipherSuiteSelector;
import org.wildfly.security.ssl.ProtocolSelector;
import org.wildfly.security.ssl.SSLUtils;
import org.wildfly.security.util.ServiceLoaderSupplier;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;

/**
 * A configuration which controls how authentication is performed.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AuthenticationConfiguration {
    // constants

    /**
     * An empty configuration which can be used as the basis for any configuration.  This configuration supports no
     * remapping of any kind, and always uses an anonymous principal.
     */
    public static final AuthenticationConfiguration EMPTY = new AuthenticationConfiguration() {

        void handleCallback(final Callback[] callbacks, final int index) throws UnsupportedCallbackException {
            CallbackUtil.unsupported(callbacks[index]);
        }

        void handleCallbacks(final AuthenticationConfiguration config, final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            final int length = callbacks.length;
            for (int i = 0; i < length; i ++) {
                config.handleCallback(callbacks, i);
            }
        }

        void configureSaslProperties(final Map<String, Object> properties) {
        }

        boolean filterOneSaslMechanism(final String mechanismName) {
            // nobody found a way to support this mechanism
            return false;
        }

        String doRewriteUser(final String original) {
            return original;
        }

        AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
            return this;
        }

        AuthenticationConfiguration without(final Class<? extends AuthenticationConfiguration> clazz) {
            return this;
        }

        String getHost(final URI uri) {
            return uri.getHost();
        }

        int getPort(final URI uri) {
            return uri.getPort();
        }

        Principal getPrincipal() {
            return AnonymousPrincipal.getInstance();
        }

        SSLContext getSslContext() {
            return null;
        }

        void configureSslEngine(final SSLEngine sslEngine) {
        }

        void configureSslSocket(final SSLSocket sslSocket) {
        }

        ProtocolSelector getProtocolSelector() {
            return ProtocolSelector.defaultProtocols();
        }

        CipherSuiteSelector getCipherSuiteSelector() {
            return CipherSuiteSelector.openSslDefault();
        }

        SecurityFactory<X509TrustManager> getX509TrustManagerFactory() {
            return SSLUtils.getDefaultX509TrustManagerSecurityFactory();
        }

        SecurityFactory<X509KeyManager> getX509KeyManagerFactory() {
            return null;
        }

        void configureKeyManager(final ConfigurationKeyManager.Builder builder) {
        }

        Supplier<Provider[]> getProviderSupplier() {
            return Security::getProviders;
        }
    }.useAnonymous().useTrustManager(null);

    private final AuthenticationConfiguration parent;
    private final CallbackHandler callbackHandler = callbacks -> AuthenticationConfiguration.this.handleCallbacks(AuthenticationConfiguration.this, callbacks);

    // constructors

    AuthenticationConfiguration() {
        this.parent = null;
    }

    AuthenticationConfiguration(final AuthenticationConfiguration parent) {
        this(parent, false);
    }

    AuthenticationConfiguration(final AuthenticationConfiguration parent, final boolean allowMultiple) {
        this.parent = allowMultiple ? parent : parent.without(getClass());
    }

    // test method

    Principal getPrincipal() {
        return parent.getPrincipal();
    }

    String getHost(URI uri) {
        return parent.getHost(uri);
    }

    int getPort(URI uri) {
        return parent.getPort(uri);
    }

    // internal actions

    void handleCallback(Callback[] callbacks, int index) throws IOException, UnsupportedCallbackException {
        parent.handleCallback(callbacks, index);
    }

    void handleCallbacks(AuthenticationConfiguration config, Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        parent.handleCallbacks(config, callbacks);
    }

    void configureSaslProperties(Map<String, Object> properties) {
        parent.configureSaslProperties(properties);
    }

    boolean filterOneSaslMechanism(String mechanismName) {
        return parent.filterOneSaslMechanism(mechanismName);
    }

    String doRewriteUser(String original) {
        return parent.doRewriteUser(original);
    }

    String getAuthorizationName() {
        return null;
    }

    SSLContext getSslContext() {
        return parent.getSslContext();
    }

    void configureSslEngine(final SSLEngine sslEngine) {
        parent.configureSslEngine(sslEngine);
    }

    void configureSslSocket(final SSLSocket sslSocket) {
        parent.configureSslSocket(sslSocket);
    }

    ProtocolSelector getProtocolSelector() {
        return parent.getProtocolSelector();
    }

    CipherSuiteSelector getCipherSuiteSelector() {
        return parent.getCipherSuiteSelector();
    }

    Supplier<Provider[]> getProviderSupplier() {
        return parent.getProviderSupplier();
    }

    SecurityFactory<X509TrustManager> getX509TrustManagerFactory() {
        return parent.getX509TrustManagerFactory();
    }

    SecurityFactory<X509KeyManager> getX509KeyManagerFactory() throws GeneralSecurityException {
        return parent.getX509KeyManagerFactory();
    }

    void configureKeyManager(ConfigurationKeyManager.Builder builder) throws GeneralSecurityException {
        parent.configureKeyManager(builder);
    }

    abstract AuthenticationConfiguration reparent(AuthenticationConfiguration newParent);

    AuthenticationConfiguration without(Class<? extends AuthenticationConfiguration> clazz) {
        if (clazz.isInstance(this)) return parent;
        AuthenticationConfiguration newParent = parent.without(clazz);
        if (parent == newParent) return this;
        return reparent(newParent);
    }

    // assembly methods - rewrite

    /**
     * Create a new configuration which is the same as this configuration, but rewrites the user name using the given
     * name rewriter.
     *
     * @param rewriter the name rewriter
     * @return the new configuration
     */
    public AuthenticationConfiguration rewriteUser(NameRewriter rewriter) {
        if (rewriter == null) {
            return this;
        }
        return new RewriteNameAuthenticationConfiguration(this, rewriter);
    }

    // assembly methods - filter

    // assembly methods - configuration

    /**
     * Create a new configuration which is the same as this configuration, but which uses an anonymous login.
     *
     * @return the new configuration
     */
    public AuthenticationConfiguration useAnonymous() {
        return new SetAnonymousAuthenticationConfiguration(this);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given principal to authenticate.
     *
     * @param principal the principal to use
     * @return the new configuration
     */
    public AuthenticationConfiguration usePrincipal(NamePrincipal principal) {
        return new SetNamePrincipalAuthenticationConfiguration(this, principal);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given login name to authenticate.
     *
     * @param name the principal to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useName(String name) {
        return usePrincipal(new NamePrincipal(name));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which attempts to authorize to the given
     * name after authentication.
     *
     * @param name the name to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useAuthorizationName(String name) {
        return new SetAuthorizationNameAuthenticationConfiguration(this, name);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @return the new configuration
     */
    public AuthenticationConfiguration usePassword(Password password) {
        return password == null ? this : new SetPasswordAuthenticationConfiguration(this, password);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @return the new configuration
     */
    public AuthenticationConfiguration usePassword(char[] password) {
        return password == null ? this : usePassword(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, password));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @return the new configuration
     */
    public AuthenticationConfiguration usePassword(String password) {
        return password == null ? this : usePassword(password.toCharArray());
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given callback handler to
     * acquire a password with which to authenticate.
     *
     * @param callbackHandler the password callback handler
     * @return the new configuration
     */
    public AuthenticationConfiguration usePasswordCallback(CallbackHandler callbackHandler) {
        return callbackHandler == null ? this : new SetPasswordCallbackHandlerAuthenticationConfiguration(this, callbackHandler);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given callback handler
     * to authenticate.
     *
     * @param callbackHandler the callback handler to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useCallbackHandler(CallbackHandler callbackHandler) {
        return callbackHandler == null ? this : new SetCallbackHandlerAuthenticationConfiguration(this, callbackHandler);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given GSS-API credential to authenticate.
     *
     * @param credential the GSS-API credential to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useGSSCredential(GSSCredential credential) {
        return credential == null ? this : new SetGSSCredentialAuthenticationConfiguration(this, credential);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given key store and alias
     * to acquire the credential required for authentication.
     *
     * @param keyStoreEntry the key store entry to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useKeyStoreCredential(KeyStore.Entry keyStoreEntry) {
        return keyStoreEntry == null ? this : new SetKeyStoreCredentialAuthenticationConfiguration(this, new FixedSecurityFactory<>(keyStoreEntry));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given key store and alias
     * to acquire the credential required for authentication.
     *
     * @param keyStore the key store to use
     * @param alias the key store alias
     * @return the new configuration
     */
    public AuthenticationConfiguration useKeyStoreCredential(KeyStore keyStore, String alias) {
        return keyStore == null || alias == null ? this : new SetKeyStoreCredentialAuthenticationConfiguration(this, keyStore, alias, null);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given key store and alias
     * to acquire the credential required for authentication.
     *
     * @param keyStore the key store to use
     * @param alias the key store alias
     * @param protectionParameter the protection parameter to use to access the key store entry
     * @return the new configuration
     */
    public AuthenticationConfiguration useKeyStoreCredential(KeyStore keyStore, String alias, KeyStore.ProtectionParameter protectionParameter) {
        return keyStore == null || alias == null ? this : new SetKeyStoreCredentialAuthenticationConfiguration(this, keyStore, alias, protectionParameter);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given private key and X.509
     * certificate chain to authenticate.
     *
     * @param privateKey the client private key
     * @param certificateChain the client certificate chain
     * @return the new configuration
     */
    public AuthenticationConfiguration useCertificateCredential(PrivateKey privateKey, X509Certificate... certificateChain) {
        return certificateChain == null || certificateChain.length == 0 || privateKey == null ? without(SetCertificateCredentialAuthenticationConfiguration.class) : useCertificateCredential(new X509CertificateChainPrivateCredential(privateKey, certificateChain));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given private key and X.509
     * certificate chain to authenticate.
     *
     * @param credential the credential containing the private key and certificate chain
     * @return the new configuration
     */
    public AuthenticationConfiguration useCertificateCredential(X509CertificateChainPrivateCredential credential) {
        return credential == null ? without(SetCertificateCredentialAuthenticationConfiguration.class) : useCertificateCredential(new FixedSecurityFactory<>(credential));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given private key and X.509
     * certificate chain to authenticate.
     *
     * @param credentialFactory a factory which produces the credential containing the private key and certificate chain
     * @return the new configuration
     */
    public AuthenticationConfiguration useCertificateCredential(SecurityFactory<X509CertificateChainPrivateCredential> credentialFactory) {
        return credentialFactory == null ? without(SetCertificateCredentialAuthenticationConfiguration.class) : new SetCertificateCredentialAuthenticationConfiguration(this, credentialFactory);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given key manager
     * to acquire the credential required for authentication.
     *
     * @param keyManager the key manager to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useKeyManagerCredential(X509KeyManager keyManager) {
        return keyManager == null ? without(SetKeyManagerCredentialAuthenticationConfiguration.class) : new SetKeyManagerCredentialAuthenticationConfiguration(this, new FixedSecurityFactory<>(keyManager));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given choice if the given
     * predicate evaluates to {@code true}.
     *
     * @param matchPredicate the predicate that should be used to determine if a choice callback type and prompt are
     *                       relevant for the given choice
     * @param choice the choice to use if the given predicate evaluates to {@code true}
     * @return the new configuration
     */
    public AuthenticationConfiguration useChoice(BiPredicate<Class<? extends ChoiceCallback>, String> matchPredicate, String choice) {
        return matchPredicate == null ? this : new SetChoiceAuthenticationConfiguration(this, matchPredicate, choice);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given trust manager
     * for trust verification.
     *
     * @param trustManager the trust manager to use or {@code null} if the default trust manager should be used
     * @return the new configuration
     */
    public AuthenticationConfiguration useTrustManager(X509TrustManager trustManager) {
        return trustManager == null ? new SetTrustManagerAuthenticationConfiguration(this, SSLUtils.getDefaultX509TrustManagerSecurityFactory()) : new SetTrustManagerAuthenticationConfiguration(this, new FixedSecurityFactory<>(trustManager));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which connects to a different host name.
     *
     * @param hostName the host name to connect to
     * @return the new configuration
     */
    public AuthenticationConfiguration useHost(String hostName) {
        if (hostName != null && hostName.isEmpty()) hostName = null;
        return new SetHostAuthenticationConfiguration(this, hostName);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which connects to a different port.
     *
     * @param port the port to connect to
     * @return the new configuration
     */
    public AuthenticationConfiguration usePort(int port) {
        if (port < 1 || port > 65535) throw log.invalidPortNumber(port);
        return new SetPortAuthenticationConfiguration(this, port);
    }

    // Providers

    /**
     * Use the given security provider supplier to locate security implementations.
     *
     * @param providerSupplier the provider supplier
     * @return the new configuration
     */
    public AuthenticationConfiguration useProviders(Supplier<Provider[]> providerSupplier) {
        return providerSupplier == null ? useDefaultProviders() : new ProvidersAuthenticationConfiguration(this, providerSupplier);
    }

    /**
     * Use the system default security providers to locate security implementations.
     *
     * @return the new configuration
     */
    public AuthenticationConfiguration useDefaultProviders() {
        return without(ProvidersAuthenticationConfiguration.class);
    }

    /**
     * Use security providers from the given class loader.
     *
     * @param classLoader the class loader to search for security providers
     * @return the new configuration
     */
    public AuthenticationConfiguration useProvidersFromClassLoader(ClassLoader classLoader) {
        return useProviders(new ServiceLoaderSupplier<Provider>(Provider.class, classLoader));
    }

    // SASL

    /**
     * Create a new configuration which is the same as this configuration, but which sets the allowed mechanism set
     * to only include the given named mechanisms.
     *
     * @param names the mechanism names
     * @return the new configuration
     */
    public AuthenticationConfiguration allowSaslMechanisms(String... names) {
        return names == null || names.length == 0 ? new FilterSaslMechanismAuthenticationConfiguration(this, true, Collections.<String>emptySet()) : new FilterSaslMechanismAuthenticationConfiguration(this, true, new HashSet<String>(Arrays.asList(names)));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which sets the allowed mechanism set
     * to all available mechanisms except for the given named mechanisms.
     *
     * @param names the mechanism names
     * @return the new configuration
     */
    public AuthenticationConfiguration forbidSaslMechanisms(String... names) {
        return names == null || names.length == 0 ? this : new FilterSaslMechanismAuthenticationConfiguration(this, false, new HashSet<String>(Arrays.asList(names)));
    }

    // SSL

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given protocol selector
     * for choosing an SSL/TLS protocol.
     *
     * @param protocolSelector the protocol selector
     * @return the new configuration
     */
    public AuthenticationConfiguration useSslProtocolSelector(ProtocolSelector protocolSelector) {
        return protocolSelector == null ? without(ProtocolSelectorAuthenticationConfiguration.class) : new ProtocolSelectorAuthenticationConfiguration(this, protocolSelector);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given cipher suite selector
     * for choosing the set of SSL/TLS cipher suites.
     *
     * @param cipherSuiteSelector the cipher suite selector
     * @return the new configuration
     */
    public AuthenticationConfiguration useSslCipherSuiteSelector(CipherSuiteSelector cipherSuiteSelector) {
        return cipherSuiteSelector == null ? without(CipherSuiteSelectorAuthenticationConfiguration.class) : new CipherSuiteSelectorAuthenticationConfiguration(this, cipherSuiteSelector);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given predefined SSL context
     * for choosing the set of SSL/TLS cipher suites.  Using a predefined SSL context will remove any configured client
     * authentication (e.g. certificates) or server trust configurations.
     *
     * @param sslContext the SSL context to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useSslContext(SSLContext sslContext) {
        return sslContext == null ? without(SSLContextAuthenticationConfiguration.class) : new SSLContextAuthenticationConfiguration(this, sslContext);
    }

    /**
     * Use the given private key and X.509 certificate chain for SSL/TLS client authentication.
     *
     * @param privateKey the client private key
     * @param certificateChain the client certificate chain
     * @return the new configuration
     */
    public AuthenticationConfiguration useSslClientCredential(PrivateKey privateKey, X509Certificate... certificateChain) {
        return certificateChain == null || certificateChain.length == 0 || privateKey == null ? without(SSLClientCertificateConfiguration.class) : useSslClientCredential(new X509CertificateChainPrivateCredential(privateKey, certificateChain));
    }

    /**
     * Use the given private key and X.509 certificate chain for SSL/TLS client authentication.
     *
     * @param credential the credential containing the private key and certificate chain
     * @return the new configuration
     */
    public AuthenticationConfiguration useSslClientCredential(X509CertificateChainPrivateCredential credential) {
        return credential == null ? without(SSLClientCertificateConfiguration.class) : useSslClientCredential(new FixedSecurityFactory<>(credential));
    }

    /**
     * Use the given private key and X.509 certificate chain for SSL/TLS client authentication.
     *
     * @param credentialFactory a factory which produces the credential containing the private key and certificate chain
     * @return the new configuration
     */
    public AuthenticationConfiguration useSslClientCredential(SecurityFactory<X509CertificateChainPrivateCredential> credentialFactory) {
        return credentialFactory == null ? without(SSLClientCertificateConfiguration.class) : new SSLClientCertificateConfiguration(this, credentialFactory);
    }

    /**
     * Use the given key manager in place of any SSL client authentication configuration.
     *
     * @param keyManager the key manager to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useSslClientKeyManager(X509KeyManager keyManager) {
        return keyManager == null ? without(SSLClientKeyManagerConfiguration.class) : new SSLClientKeyManagerConfiguration(this, new FixedSecurityFactory<>(keyManager));
    }

    public AuthenticationConfiguration useRealm(String realm) {
        return new SetRealmAuthenticationConfiguration(this, realm);
    }

    // client methods

    CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

    SaslClient createSaslClient(URI uri, SaslClientFactory clientFactory, Collection<String> serverMechanisms) throws SaslException {
        final HashMap<String, Object> properties = new HashMap<String, Object>();
        configureSaslProperties(properties);
        final HashSet<String> mechs = new HashSet<String>(serverMechanisms);
        mechs.removeIf(n -> ! filterOneSaslMechanism(n));
        final String authorizationName = getAuthorizationName();
        final CallbackHandler callbackHandler = getCallbackHandler();
        return clientFactory.createSaslClient(mechs.toArray(new String[mechs.size()]), authorizationName, uri.getScheme(), getHost(uri), properties, callbackHandler);
    }

    InetSocketAddress getDestinationInetAddress(URI uri, int defaultPort) {
        final String host = getHost(uri);
        int port = getPort(uri);
        if (port == -1) port = defaultPort;
        return new InetSocketAddress(host, port);
    }

    SSLContext createSslContext() throws GeneralSecurityException {
        SSLContext sslContext = getSslContext();
        if (sslContext == null) {
            sslContext = SSLContext.getDefault();
        } else {
            final SecurityFactory<SSLContext> sslContextFactory = SSLUtils.createSslContextFactory(getProtocolSelector(), getProviderSupplier());
            sslContext = sslContextFactory.create();
            final SecurityFactory<X509KeyManager> keyManagerFactory = getX509KeyManagerFactory();
            final KeyManager keyManager;
            if (keyManagerFactory != null) {
                keyManager = keyManagerFactory.create();
            } else {
                final ConfigurationKeyManager.Builder builder = ConfigurationKeyManager.builder();
                configureKeyManager(builder);
                keyManager = builder.build();
            }
            final KeyManager[] keyManagers = new KeyManager[] { keyManager };
            final SecurityFactory<X509TrustManager> trustManagerFactory = getX509TrustManagerFactory();
            final TrustManager trustManager;
            if (trustManagerFactory != null) {
                trustManager = trustManagerFactory.create();
            } else {
                // should never happen though
                trustManager = null;
            }
            final TrustManager[] trustManagers = new TrustManager[] { trustManager };
            sslContext.init(keyManagers, trustManagers, null);
        }
        return SSLUtils.createConfiguredSslContext(sslContext, new ClientSSLConfigurator(this));
    }
}
