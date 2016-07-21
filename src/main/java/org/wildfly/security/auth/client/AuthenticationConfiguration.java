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
import java.net.URI;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
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
import org.wildfly.common.Assert;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.credential.GSSCredentialCredential;
import org.wildfly.security.credential.source.CallbackHandlerCredentialSource;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.credential.source.CredentialStoreCredentialSource;
import org.wildfly.security.credential.source.KeyStoreCredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.sasl.util.FilterMechanismSaslClientFactory;
import org.wildfly.security.sasl.util.PropertiesSaslClientFactory;
import org.wildfly.security.sasl.util.ProtocolSaslClientFactory;
import org.wildfly.security.sasl.util.SecurityProviderSaslClientFactory;
import org.wildfly.security.sasl.util.ServerNameSaslClientFactory;
import org.wildfly.security.ssl.CipherSuiteSelector;
import org.wildfly.security.ssl.ProtocolSelector;
import org.wildfly.security.ssl.SSLUtils;
import org.wildfly.security.util.ServiceLoaderSupplier;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;

/**
 * A configuration which controls how authentication is performed.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
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

        AuthenticationConfiguration without(final Class<?> clazz) {
            return this;
        }

        AuthenticationConfiguration without(Class<?> clazz1, Class<?> clazz2) {
            return this;
        }

        String getHost() {
            return null;
        }

        String getProtocol() {
            return null;
        }

        int getPort() {
            return -1;
        }

        Principal getPrincipal() {
            return AnonymousPrincipal.getInstance();
        }

        String getAuthorizationName() {
            return null;
        }

        SSLContext getSslContext() throws NoSuchAlgorithmException {
            return SSLContext.getDefault();
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

        @Override
        SaslClientFactory getSaslClientFactory(Supplier<Provider[]> providers) {
            return new SecurityProviderSaslClientFactory(providers);
        }

        boolean delegatesThrough(final Class<?> clazz) {
            return false;
        }

        CredentialSource getCredentialSource() {
            return CredentialSource.NONE;
        }

        @Override
        StringBuilder asString(StringBuilder sb) {
            return sb;
        }

    }.useAnonymous().useTrustManager(null);

    private final AuthenticationConfiguration parent;
    private final CallbackHandler callbackHandler = callbacks -> AuthenticationConfiguration.this.handleCallbacks(AuthenticationConfiguration.this, callbacks);
    private SaslClientFactory saslClientFactory = null;

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

    String getHost() {
        return parent.getHost();
    }

    String getProtocol() {
        return parent.getProtocol();
    }

    int getPort() {
        return parent.getPort();
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
        return parent.getAuthorizationName();
    }

    SSLContext getSslContext() throws GeneralSecurityException {
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

    SaslClientFactory getSaslClientFactory(Supplier<Provider[]> providers) {
        return parent.getSaslClientFactory(providers);
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

    CredentialSource getCredentialSource() {
        return parent.getCredentialSource();
    }

    abstract AuthenticationConfiguration reparent(AuthenticationConfiguration newParent);

    AuthenticationConfiguration without(Class<?> clazz) {
        if (clazz.isInstance(this)) return parent;
        AuthenticationConfiguration newParent = parent.without(clazz);
        if (parent == newParent) return this;
        return reparent(newParent);
    }

    AuthenticationConfiguration without(Class<?> clazz1, Class<?> clazz2) {
        if (clazz1.isInstance(this) && clazz2.isInstance(this)) return parent;
        if (clazz1.isInstance(this)) return parent.without(clazz2);
        if (clazz2.isInstance(this)) return parent.without(clazz1);
        AuthenticationConfiguration newParent = parent.without(clazz1, clazz2);
        if (parent == newParent) return this;
        return reparent(newParent);
    }

    boolean delegatesThrough(Class<?> clazz) {
        return clazz.isInstance(this) || parent.delegatesThrough(clazz);
    }

    // assembly methods - rewrite

    /**
     * Create a new configuration which is the same as this configuration, but rewrites the user name using the given
     * name rewriter.
     *
     * @param rewriter the name rewriter
     * @return the new configuration
     */
    public final AuthenticationConfiguration rewriteUser(NameRewriter rewriter) {
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
    public final AuthenticationConfiguration useAnonymous() {
        return new SetAnonymousAuthenticationConfiguration(this);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given principal to authenticate.
     *
     * @param principal the principal to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration usePrincipal(NamePrincipal principal) {
        return new SetNamePrincipalAuthenticationConfiguration(this, principal);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given login name to authenticate.
     *
     * @param name the principal to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration useName(String name) {
        return usePrincipal(new NamePrincipal(name));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which attempts to authorize to the given
     * name after authentication.
     *
     * @param name the name to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration useAuthorizationName(String name) {
        return new SetAuthorizationNameAuthenticationConfiguration(this, name);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration usePassword(Password password) {
        final CredentialSource filtered = getCredentialSource().without(PasswordCredential.class);
        return password == null ? useCredentials(filtered) : useCredentials(filtered.with(IdentityCredentials.NONE.withCredential(new PasswordCredential(password))));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration usePassword(char[] password) {
        return usePassword(password == null ? null : ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, password));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration usePassword(String password) {
        return usePassword(password == null ? null : ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, password.toCharArray()));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @param matchPredicate the predicate to determine if a password callback prompt is relevant for the given password or
     *                       {@code null} to use the given password regardless of the prompt
     * @return the new configuration
     */
    public final AuthenticationConfiguration usePassword(Password password, Predicate<String> matchPredicate) {
        return usePassword(password);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @param matchPredicate the predicate to determine if a password callback prompt is relevant for the given password or
     *                       {@code null} to use the given password regardless of the prompt
     * @return the new configuration
     */
    public final AuthenticationConfiguration usePassword(char[] password, Predicate<String> matchPredicate) {
        return usePassword(password);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @param matchPredicate the predicate to determine if a password callback prompt is relevant for the given password or
     *                       {@code null} to use the given password regardless of the prompt
     * @return the new configuration
     */
    public final AuthenticationConfiguration usePassword(String password, Predicate<String> matchPredicate) {
        return usePassword(password);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given callback handler to
     * acquire a password with which to authenticate, when a password-based authentication algorithm is in use.
     *
     * @param callbackHandler the password callback handler
     * @return the new configuration
     */
    public final AuthenticationConfiguration useCredentialCallbackHandler(CallbackHandler callbackHandler) {
        return callbackHandler == null ? this : useCredentials(new CallbackHandlerCredentialSource(callbackHandler).with(getCredentialSource()));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given callback handler
     * to authenticate.
     *
     * @param callbackHandler the callback handler to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration useCallbackHandler(CallbackHandler callbackHandler) {
        return callbackHandler == null ? this : new SetCallbackHandlerAuthenticationConfiguration(this, callbackHandler);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given GSS-API credential to authenticate.
     *
     * @param credential the GSS-API credential to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration useGSSCredential(GSSCredential credential) {
        return credential == null ? this : useCredentials(getCredentialSource().with(IdentityCredentials.NONE.withCredential(new GSSCredentialCredential(credential))));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given key store and alias
     * to acquire the credential required for authentication.
     *
     * @param keyStoreEntry the key store entry to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration useKeyStoreCredential(KeyStore.Entry keyStoreEntry) {
        return keyStoreEntry == null ? this : useCredentials(getCredentialSource().with(new KeyStoreCredentialSource(new FixedSecurityFactory<>(keyStoreEntry))));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given key store and alias
     * to acquire the credential required for authentication.
     *
     * @param keyStore the key store to use
     * @param alias the key store alias
     * @return the new configuration
     */
    public final AuthenticationConfiguration useKeyStoreCredential(KeyStore keyStore, String alias) {
        return keyStore == null || alias == null ? this : useCredentials(getCredentialSource().with(new KeyStoreCredentialSource(keyStore, alias, null)));
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
    public final AuthenticationConfiguration useKeyStoreCredential(KeyStore keyStore, String alias, KeyStore.ProtectionParameter protectionParameter) {
        return keyStore == null || alias == null ? this : useCredentials(getCredentialSource().with(new KeyStoreCredentialSource(keyStore, alias, protectionParameter)));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given private key and X.509
     * certificate chain to authenticate.
     *
     * @param privateKey the client private key
     * @param certificateChain the client certificate chain
     * @return the new configuration
     */
    public final AuthenticationConfiguration useCertificateCredential(PrivateKey privateKey, X509Certificate... certificateChain) {
        return certificateChain == null || certificateChain.length == 0 || privateKey == null ? this : useCertificateCredential(new X509CertificateChainPrivateCredential(privateKey, certificateChain));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given private key and X.509
     * certificate chain to authenticate.
     *
     * @param credential the credential containing the private key and certificate chain
     * @return the new configuration
     */
    public final AuthenticationConfiguration useCertificateCredential(X509CertificateChainPrivateCredential credential) {
        return credential == null ? this : useCredentials(getCredentialSource().with(IdentityCredentials.NONE.withCredential(credential)));
    }

    /**
     * Create a new configuration which is the same as this configuration, but it has {@link CredentialStoreReference}
     * attached for referencing {@link org.wildfly.security.credential.store.CredentialStore} alias with given type.
     * For more see {@link CredentialStoreReference}.
     *
     * @see CredentialStoreReference
     * @param credentialStoreReference of {@link CredentialStoreReference}
     * @return the new configuration
     */
    public AuthenticationConfiguration useCredentialStoreReference(SecurityFactory<CredentialStore> credentialStoreFactory, CredentialStoreReference credentialStoreReference) {
        Assert.checkNotNullParam("credentialStoreReference", credentialStoreReference);
        CredentialStoreCredentialSource csCredentialSource = new CredentialStoreCredentialSource(credentialStoreFactory, credentialStoreReference);
        return useCredentials(getCredentialSource().with(csCredentialSource));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given key manager
     * to acquire the credential required for authentication.
     *
     * @param keyManager the key manager to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration useKeyManagerCredential(X509KeyManager keyManager) {
        return keyManager == null ? without(SetKeyManagerCredentialAuthenticationConfiguration.class) : new SetKeyManagerCredentialAuthenticationConfiguration(this, new FixedSecurityFactory<>(keyManager));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given identity
     * credentials to acquire the credential required for authentication.
     *
     * @param credentials the credentials to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration useCredentials(CredentialSource credentials) {
        return credentials == null ? without(SetCredentialsConfiguration.class) : new SetCredentialsConfiguration(this, credentials);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given identity
     * credentials to acquire the credential required for authentication.
     *
     * @param credentials the credentials to use
     * @param matchPredicate the predicate to determine if a callback prompt is relevant for the given credentials or
     *                       {@code null} to use the given credentials regardless of the prompt
     * @return the new configuration
     */
    public final AuthenticationConfiguration useCredentials(CredentialSource credentials, Predicate<String> matchPredicate) {
        return useCredentials(credentials);
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
    public final AuthenticationConfiguration useChoice(BiPredicate<Class<? extends ChoiceCallback>, String> matchPredicate, String choice) {
        return matchPredicate == null ? this : new SetChoiceAuthenticationConfiguration(this, matchPredicate, choice);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given parameter specification.
     *
     * @param parameterSpec the algorithm parameter specification to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration useParameterSpec(AlgorithmParameterSpec parameterSpec) {
        return parameterSpec == null ? this : new SetParameterSpecAuthenticationConfiguration(this, parameterSpec);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given trust manager
     * for trust verification.
     *
     * @param trustManager the trust manager to use or {@code null} if the default trust manager should be used
     * @return the new configuration
     */
    public final AuthenticationConfiguration useTrustManager(X509TrustManager trustManager) {
        return trustManager == null ? new SetTrustManagerAuthenticationConfiguration(this, SSLUtils.getDefaultX509TrustManagerSecurityFactory()) : new SetTrustManagerAuthenticationConfiguration(this, new FixedSecurityFactory<>(trustManager));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which connects to a different host name.
     *
     * @param hostName the host name to connect to
     * @return the new configuration
     */
    public final AuthenticationConfiguration useHost(String hostName) {
        if (hostName == null || hostName.isEmpty()) {
            return without(SetHostAuthenticationConfiguration.class);
        }
        return new SetHostAuthenticationConfiguration(this, hostName);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which specifies a different protocol to be passed to the authentication mechanisms.
     *
     * @param protocol the protocol to pass to the authentication mechanisms.
     * @return the new configuration
     */
    public final AuthenticationConfiguration useProtocol(String protocol) {
        if (protocol == null || protocol.isEmpty()) {
            return without(SetProtocolAuthenticationConfiguration.class);
        }
        return new SetProtocolAuthenticationConfiguration(this, protocol);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which connects to a different port.
     *
     * @param port the port to connect to
     * @return the new configuration
     */
    public final AuthenticationConfiguration usePort(int port) {
        if (port < 1 || port > 65535) throw log.invalidPortNumber(port);
        return new SetPortAuthenticationConfiguration(this, port);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which forwards the authentication name
     * and credentials from the current identity of the given security domain.
     *
     * @param securityDomain the security domain (must not be {@code null})
     * @return the new configuration
     */
    public final AuthenticationConfiguration useForwardedIdentity(SecurityDomain securityDomain) {
        Assert.checkNotNullParam("securityDomain", securityDomain);
        final AccessControlContext context = AccessController.getContext();
        return new SetForwardAuthenticationConfiguration(this, securityDomain, context);
    }

    // Providers

    /**
     * Use the given security provider supplier to locate security implementations.
     *
     * @param providerSupplier the provider supplier
     * @return the new configuration
     */
    public final AuthenticationConfiguration useProviders(Supplier<Provider[]> providerSupplier) {
        return providerSupplier == null ? useDefaultProviders() : new ProvidersAuthenticationConfiguration(this, providerSupplier);
    }

    /**
     * Use the system default security providers to locate security implementations.
     *
     * @return the new configuration
     */
    public final AuthenticationConfiguration useDefaultProviders() {
        return without(ProvidersAuthenticationConfiguration.class);
    }

    /**
     * Use security providers from the given class loader.
     *
     * @param classLoader the class loader to search for security providers
     * @return the new configuration
     */
    public final AuthenticationConfiguration useProvidersFromClassLoader(ClassLoader classLoader) {
        return useProviders(new ServiceLoaderSupplier<Provider>(Provider.class, classLoader));
    }

    // SASL Mechanisms

    /**
     * Use a pre-existing {@link SaslClientFactory} instead of discovery.
     *
     * @param saslClientFactory the pre-existing {@link SaslClientFactory} to use.
     * @return the new configuration.
     */
    public final AuthenticationConfiguration useSaslClientFactory(final SaslClientFactory saslClientFactory) {
        return useSaslClientFactory(() -> saslClientFactory);
    }

    /**
     * Use the given sasl client factory supplier to obtain the {@link SaslClientFactory} to use.
     *
     * @param saslClientFactory the sasl client factory supplier to use.
     * @return the new configuration.
     */
    public final AuthenticationConfiguration useSaslClientFactory(final Supplier<SaslClientFactory> saslClientFactory) {
        return new SetSaslClientFactoryAuthenticationConfiguration(this, saslClientFactory);
    }

    /**
     * Use provider based discovery to load available {@link SaslClientFactory} implementations.
     *
     * @return the new configuration.
     */
    public final AuthenticationConfiguration useSaslClientFactoryFromProviders() {
        return without(SetSaslClientFactoryAuthenticationConfiguration.class);
    }

    // SASL Configuration

    /**
     * Create a new configuration which is the same as this configuration, but which sets the properties that will be passed to
     * the {@code SaslClientFactory} when the mechanism is created.
     *
     * @param mechanismProperties the properties to be passed to the {@code SaslClientFactory} to create the mechanism.
     * @return the new configuration.
     */
    public final AuthenticationConfiguration useMechanismProperties(Map<String, String> mechanismProperties) {
        return mechanismProperties == null || mechanismProperties.isEmpty() ? this : new SetMechanismPropertiesConfiguration(this, mechanismProperties);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which allows all SASL mechanisms.
     *
     * @return the new configuration.
     */
    public final AuthenticationConfiguration allowAllSaslMechanisms() {
        return new SetAllowAllSaslMechanisms(this);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which sets the allowed mechanism set
     * to only include the given named mechanisms.
     *
     * @param names the mechanism names
     * @return the new configuration
     */
    public final AuthenticationConfiguration allowSaslMechanisms(String... names) {
        return names == null || names.length == 0 ? new FilterSaslMechanismAuthenticationConfiguration(this, true, Collections.<String>emptySet()) : new FilterSaslMechanismAuthenticationConfiguration(this, true, new HashSet<String>(Arrays.asList(names)));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which sets the allowed mechanism set
     * to all available mechanisms except for the given named mechanisms.
     *
     * @param names the mechanism names
     * @return the new configuration
     */
    public final AuthenticationConfiguration forbidSaslMechanisms(String... names) {
        return names == null || names.length == 0 ? this : new FilterSaslMechanismAuthenticationConfiguration(this, false, new HashSet<String>(Arrays.asList(names)));
    }

    // SSL

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given predefined SSL context
     * for choosing the set of SSL/TLS cipher suites, performing authentication, etc.
     *
     * @param sslContext the SSL context to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration useSslContext(SSLContext sslContext) {
        return sslContext == null ? without(SSLContextAuthenticationConfiguration.class) : new SSLContextAuthenticationConfiguration(this, sslContext);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given predefined SSL context
     * for choosing the set of SSL/TLS cipher suites, performing authentication, etc.
     *
     * @param sslContextFactory the SSL context factory to use
     * @return the new configuration
     */
    public final AuthenticationConfiguration useSslContext(SecurityFactory<SSLContext> sslContextFactory) {
        return sslContextFactory == null ? without(SSLContextAuthenticationConfiguration.class) : new SSLContextAuthenticationConfiguration(this, sslContextFactory);
    }

    // other

    public final AuthenticationConfiguration useRealm(String realm) {
        return new SetRealmAuthenticationConfiguration(this, realm);
    }

    // client methods

    final CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

    /**
     * Get the {@link SaslClientFactory} for this factory, either using a cached instance or creating if required.
     * @return
     */
    private SaslClientFactory getSaslClientFactory() {
        if (saslClientFactory == null) {
            synchronized (this) {
                if (saslClientFactory == null) {
                    saslClientFactory = getSaslClientFactory(getProviderSupplier());
                }
            }
        }
        return saslClientFactory;
    }

    final SaslClient createSaslClient(URI uri, Collection<String> serverMechanisms, UnaryOperator<SaslClientFactory> factoryOperator) throws SaslException {
        SaslClientFactory saslClientFactory = factoryOperator.apply(getSaslClientFactory());

        final HashMap<String, Object> properties = new HashMap<String, Object>();
        configureSaslProperties(properties);
        if (properties.isEmpty() == false) {
            saslClientFactory = new PropertiesSaslClientFactory(saslClientFactory, properties);
        }
        String host = getHost();
        if (host != null) {
            saslClientFactory = new ServerNameSaslClientFactory(saslClientFactory, host);
        }
        String protocol = getProtocol();
        if (protocol != null) {
            saslClientFactory = new ProtocolSaslClientFactory(saslClientFactory, protocol);
        }
        saslClientFactory = new FilterMechanismSaslClientFactory(saslClientFactory, this::filterOneSaslMechanism);

        return saslClientFactory.createSaslClient(serverMechanisms.toArray(new String[serverMechanisms.size()]),
                getAuthorizationName(), uri.getScheme(), uri.getHost(), Collections.emptyMap(), getCallbackHandler());
    }

    // String Representation

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        asString(sb);
        sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    abstract StringBuilder asString(StringBuilder sb);

    final StringBuilder parentAsString(StringBuilder sb) {
        return parent.asString(sb);
    }

    // interfaces

    interface UserSetting {}
    interface CredentialSetting {}
}
