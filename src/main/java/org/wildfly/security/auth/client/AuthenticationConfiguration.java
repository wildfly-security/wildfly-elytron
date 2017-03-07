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

import static java.security.AccessController.doPrivileged;
import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.net.URI;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.ietf.jgss.GSSCredential;
import org.wildfly.common.Assert;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.ParameterCallback;
import org.wildfly.security.auth.callback.PasswordResetCallback;
import org.wildfly.security.auth.callback.TrustedAuthoritiesCallback;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.GSSKerberosCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.source.CredentialStoreCredentialSource;
import org.wildfly.security.credential.source.KeyStoreCredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.localuser.LocalUserSaslFactory;
import org.wildfly.security.sasl.util.FilterMechanismSaslClientFactory;
import org.wildfly.security.sasl.util.PropertiesSaslClientFactory;
import org.wildfly.security.sasl.util.ProtocolSaslClientFactory;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.sasl.util.SecurityProviderSaslClientFactory;
import org.wildfly.security.sasl.util.ServerNameSaslClientFactory;
import org.wildfly.security.ssl.SSLUtils;
import org.wildfly.security.util.ServiceLoaderSupplier;
import org.wildfly.security.x500.TrustedAuthority;

/**
 * A configuration which controls how authentication is performed.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class AuthenticationConfiguration {
    // constants

    private static final Principal[] NO_PRINCIPALS = new Principal[0];
    private static final Callback[] NO_CALLBACKS = new Callback[0];
    private static final String[] NO_STRINGS = new String[0];

    private static final EnumSet<CallbackKind> NO_CALLBACK_KINDS = EnumSet.noneOf(CallbackKind.class);

    private static final int SET_PRINCIPAL = 0;
    private static final int SET_HOST = 1;
    private static final int SET_PROTOCOL = 2;
    private static final int SET_REALM = 3;
    private static final int SET_AUTHZ_NAME = 4;
    private static final int SET_FWD_DOMAIN = 5;
    private static final int SET_USER_CBH = 6;
    private static final int SET_USER_CB_KINDS = 7;
    private static final int SET_CRED_SOURCE = 8;
    private static final int SET_PROVIDER_SUPPLIER = 9;
    private static final int SET_KEY_MGR_FAC = 10;
    private static final int SET_ALLOWED_SASL = 11;
    private static final int SET_DENIED_SASL = 12;
    private static final int SET_PRINCIPAL_RW = 13;
    private static final int SET_SASL_FAC_SUP = 14;
    private static final int SET_PARAM_SPECS = 15;
    private static final int SET_TRUST_MGR_FAC = 16;
    private static final int SET_MECH_PROPS = 17;
    private static final int SET_ACCESS_CTXT = 18;
    private static final int SET_CALLBACK_INTERCEPT = 19;

    /**
     * An empty configuration which can be used as the basis for any configuration.  This configuration supports no
     * remapping of any kind, and always uses an anonymous principal.
     */
    public static final AuthenticationConfiguration EMPTY = new AuthenticationConfiguration();

    private SaslClientFactory saslClientFactory = null;
    private int hashCode;
    private String toString;

    final AccessControlContext capturedAccessContext;
    final Principal principal;
    final String setHost;
    final String setProtocol;
    final String setRealm;
    final String setAuthzName;
    final SecurityDomain forwardSecurityDomain;
    final CallbackHandler userCallbackHandler;
    final EnumSet<CallbackKind> userCallbackKinds;
    final CredentialSource credentialSource;
    final int setPort;
    final Supplier<Provider[]> providerSupplier;
    final SecurityFactory<X509KeyManager> keyManagerFactory;
    final Set<String> allowedSasl;
    final Set<String> deniedSasl;
    final Function<Principal, Principal> principalRewriter;
    final Supplier<SaslClientFactory> saslClientFactorySupplier;
    final List<AlgorithmParameterSpec> parameterSpecs;
    final SecurityFactory<X509TrustManager> trustManagerFactory;
    final Map<String, ?> mechanismProperties;
    final Predicate<Callback> callbackIntercept;

    // constructors

    /**
     * Construct the empty configuration instance.
     */
    private AuthenticationConfiguration() {
        this.capturedAccessContext = null;
        this.principal = null;
        this.setHost = null;
        this.setProtocol = null;
        this.setRealm = null;
        this.setAuthzName = null;
        this.forwardSecurityDomain = null;
        this.userCallbackHandler = null;
        this.userCallbackKinds = NO_CALLBACK_KINDS;
        this.credentialSource = IdentityCredentials.NONE;
        this.setPort = -1;
        this.providerSupplier = null;
        this.keyManagerFactory = null;
        this.allowedSasl = Collections.emptySet();
        this.deniedSasl = Collections.emptySet();
        this.principalRewriter = null;
        this.saslClientFactorySupplier = null;
        this.parameterSpecs = Collections.emptyList();
        this.trustManagerFactory = null;
        this.mechanismProperties = Collections.emptyMap();
        this.callbackIntercept = null;
    }

    /**
     * Copy constructor for mutating one object field.  It's not pretty but the alternative (many constructors) is much
     * worse.
     *
     * @param original the original configuration (must not be {@code null})
     * @param what the field to mutate
     * @param value the field value to set
     */
    @SuppressWarnings("unchecked")
    private AuthenticationConfiguration(final AuthenticationConfiguration original, final int what, final Object value) {
        this.capturedAccessContext = what == SET_ACCESS_CTXT ? (AccessControlContext) value : original.capturedAccessContext;
        this.principal = what == SET_PRINCIPAL ? (Principal) value : original.principal;
        this.setHost = what == SET_HOST ? (String) value : original.setHost;
        this.setProtocol = what == SET_PROTOCOL ? (String) value : original.setProtocol;
        this.setRealm = what == SET_REALM ? (String) value : original.setRealm;
        this.setAuthzName = what == SET_AUTHZ_NAME ? (String) value : original.setAuthzName;
        this.forwardSecurityDomain = what == SET_FWD_DOMAIN ? (SecurityDomain) value : original.forwardSecurityDomain;
        this.userCallbackHandler = what == SET_USER_CBH ? (CallbackHandler) value : original.userCallbackHandler;
        this.userCallbackKinds = what == SET_USER_CB_KINDS ? (EnumSet<CallbackKind>) value : original.userCallbackKinds;
        this.credentialSource = what == SET_CRED_SOURCE ? (CredentialSource) value : original.credentialSource;
        this.setPort = original.setPort;
        this.providerSupplier = what == SET_PROVIDER_SUPPLIER ? (Supplier<Provider[]>) value : original.providerSupplier;
        this.keyManagerFactory = what == SET_KEY_MGR_FAC ? (SecurityFactory<X509KeyManager>) value : original.keyManagerFactory;
        this.allowedSasl = what == SET_ALLOWED_SASL ? (Set<String>) value : original.allowedSasl;
        this.deniedSasl = what == SET_DENIED_SASL ? (Set<String>) value : original.deniedSasl;
        this.principalRewriter = what == SET_PRINCIPAL_RW ? (Function<Principal, Principal>) value : original.principalRewriter;
        this.saslClientFactorySupplier = what == SET_SASL_FAC_SUP ? (Supplier<SaslClientFactory>) value : original.saslClientFactorySupplier;
        this.parameterSpecs = what == SET_PARAM_SPECS ? (List<AlgorithmParameterSpec>) value : original.parameterSpecs;
        this.trustManagerFactory = what == SET_TRUST_MGR_FAC ? (SecurityFactory<X509TrustManager>) value : original.trustManagerFactory;
        this.mechanismProperties = what == SET_MECH_PROPS ? (Map<String, ?>) value : original.mechanismProperties;
        this.callbackIntercept = what == SET_CALLBACK_INTERCEPT ? (Predicate<Callback>) value : original.callbackIntercept;
    }

    /**
     * Copy constructor for mutating two object fields.  It's not pretty but the alternative (many constructors) is much
     * worse.
     *
     * @param original the original configuration (must not be {@code null})
     * @param what1 the field to mutate
     * @param value1 the field value to set
     * @param what2 the field to mutate
     * @param value2 the field value to set
     */
    @SuppressWarnings("unchecked")
    private AuthenticationConfiguration(final AuthenticationConfiguration original, final int what1, final Object value1, final int what2, final Object value2) {
        this.capturedAccessContext = what1 == SET_ACCESS_CTXT ? (AccessControlContext) value1 : what2 == SET_ACCESS_CTXT ? (AccessControlContext) value2 : original.capturedAccessContext;
        this.principal = what1 == SET_PRINCIPAL ? (Principal) value1 : what2 == SET_PRINCIPAL ? (Principal) value2 : original.principal;
        this.setHost = what1 == SET_HOST ? (String) value1 : what2 == SET_HOST ? (String) value2 : original.setHost;
        this.setProtocol = what1 == SET_PROTOCOL ? (String) value1 : what2 == SET_PROTOCOL ? (String) value2 : original.setProtocol;
        this.setRealm = what1 == SET_REALM ? (String) value1 : what2 == SET_REALM ? (String) value2 : original.setRealm;
        this.setAuthzName = what1 == SET_AUTHZ_NAME ? (String) value1 : what2 == SET_AUTHZ_NAME ? (String) value2 : original.setAuthzName;
        this.forwardSecurityDomain = what1 == SET_FWD_DOMAIN ? (SecurityDomain) value1 : what2 == SET_FWD_DOMAIN ? (SecurityDomain) value2 : original.forwardSecurityDomain;
        this.userCallbackHandler = what1 == SET_USER_CBH ? (CallbackHandler) value1 : what2 == SET_USER_CBH ? (CallbackHandler) value2 : original.userCallbackHandler;
        this.userCallbackKinds = what1 == SET_USER_CB_KINDS ? (EnumSet<CallbackKind>) value1 : what2 == SET_USER_CB_KINDS ? (EnumSet<CallbackKind>) value2 : original.userCallbackKinds;
        this.credentialSource = what1 == SET_CRED_SOURCE ? (CredentialSource) value1 : what2 == SET_CRED_SOURCE ? (CredentialSource) value2 : original.credentialSource;
        this.setPort = original.setPort;
        this.providerSupplier = what1 == SET_PROVIDER_SUPPLIER ? (Supplier<Provider[]>) value1 : what2 == SET_PROVIDER_SUPPLIER ? (Supplier<Provider[]>) value2 : original.providerSupplier;
        this.keyManagerFactory = what1 == SET_KEY_MGR_FAC ? (SecurityFactory<X509KeyManager>) value1 : what2 == SET_KEY_MGR_FAC ? (SecurityFactory<X509KeyManager>) value2 : original.keyManagerFactory;
        this.allowedSasl = what1 == SET_ALLOWED_SASL ? (Set<String>) value1 : what2 == SET_ALLOWED_SASL ? (Set<String>) value2 : original.allowedSasl;
        this.deniedSasl = what1 == SET_DENIED_SASL ? (Set<String>) value1 : what2 == SET_DENIED_SASL ? (Set<String>) value2 : original.deniedSasl;
        this.principalRewriter = what1 == SET_PRINCIPAL_RW ? (Function<Principal, Principal>) value1 : what2 == SET_PRINCIPAL_RW ? (Function<Principal, Principal>) value2 : original.principalRewriter;
        this.saslClientFactorySupplier = what1 == SET_SASL_FAC_SUP ? (Supplier<SaslClientFactory>) value1 : what2 == SET_SASL_FAC_SUP ? (Supplier<SaslClientFactory>) value2 : original.saslClientFactorySupplier;
        this.parameterSpecs = what1 == SET_PARAM_SPECS ? (List<AlgorithmParameterSpec>) value1 : what2 == SET_PARAM_SPECS ? (List<AlgorithmParameterSpec>) value2 : original.parameterSpecs;
        this.trustManagerFactory = what1 == SET_TRUST_MGR_FAC ? (SecurityFactory<X509TrustManager>) value1 : what2 == SET_TRUST_MGR_FAC ? (SecurityFactory<X509TrustManager>) value2 : original.trustManagerFactory;
        this.mechanismProperties = what1 == SET_MECH_PROPS ? (Map<String, ?>) value1 : what2 == SET_MECH_PROPS ? (Map<String, ?>) value2 : original.mechanismProperties;
        this.callbackIntercept = what1 == SET_CALLBACK_INTERCEPT ? (Predicate<Callback>) value1 : what2 == SET_CALLBACK_INTERCEPT ? (Predicate<Callback>) value2 : original.callbackIntercept;
    }

    /**
     * Copy constructor for mutating the port number.
     *
     * @param original the original configuration (must not be {@code null})
     * @param port the port number
     */
    private AuthenticationConfiguration(final AuthenticationConfiguration original, final int port) {
        this.capturedAccessContext = original.capturedAccessContext;
        this.principal = original.principal;
        this.setHost = original.setHost;
        this.setProtocol = original.setProtocol;
        this.setRealm = original.setRealm;
        this.setAuthzName = original.setAuthzName;
        this.forwardSecurityDomain = original.forwardSecurityDomain;
        this.userCallbackHandler = original.userCallbackHandler;
        this.userCallbackKinds = original.userCallbackKinds;
        this.credentialSource = original.credentialSource;
        this.setPort = port;
        this.providerSupplier = original.providerSupplier;
        this.keyManagerFactory = original.keyManagerFactory;
        this.allowedSasl = original.allowedSasl;
        this.deniedSasl = original.deniedSasl;
        this.principalRewriter = original.principalRewriter;
        this.saslClientFactorySupplier = original.saslClientFactorySupplier;
        this.parameterSpecs = original.parameterSpecs;
        this.trustManagerFactory = original.trustManagerFactory;
        this.mechanismProperties = original.mechanismProperties;
        this.callbackIntercept = original.callbackIntercept;
    }

    private AuthenticationConfiguration(final AuthenticationConfiguration original, final AuthenticationConfiguration other) {
        this.capturedAccessContext = getOrDefault(other.capturedAccessContext, original.capturedAccessContext);
        this.principal = getOrDefault(other.principal, original.principal);
        this.setHost = getOrDefault(other.setHost, original.setHost);
        this.setProtocol = getOrDefault(other.setProtocol, original.setProtocol);
        this.setRealm = getOrDefault(other.setRealm, original.setRealm);
        this.setAuthzName = getOrDefault(other.setAuthzName, original.setAuthzName);
        this.forwardSecurityDomain = getOrDefault(other.forwardSecurityDomain, original.forwardSecurityDomain);
        this.userCallbackHandler = getOrDefault(other.userCallbackHandler, original.userCallbackHandler);
        this.userCallbackKinds = getOrDefault(other.userCallbackKinds, original.userCallbackKinds);
        this.credentialSource = getOrDefault(other.credentialSource, original.credentialSource);
        this.setPort = getOrDefault(other.setPort, original.setPort);
        this.providerSupplier = getOrDefault(other.providerSupplier, original.providerSupplier);
        this.keyManagerFactory = getOrDefault(other.keyManagerFactory, original.keyManagerFactory);
        this.allowedSasl = getOrDefault(other.allowedSasl, original.allowedSasl);
        this.deniedSasl = getOrDefault(other.deniedSasl, original.deniedSasl);
        this.principalRewriter = getOrDefault(other.principalRewriter, original.principalRewriter);
        this.saslClientFactorySupplier = getOrDefault(other.saslClientFactorySupplier, original.saslClientFactorySupplier);
        this.parameterSpecs = getOrDefault(other.parameterSpecs, original.parameterSpecs);
        this.trustManagerFactory = getOrDefault(other.trustManagerFactory, original.trustManagerFactory);
        this.mechanismProperties = getOrDefault(other.mechanismProperties, original.mechanismProperties);
        this.callbackIntercept = other.callbackIntercept == null ? original.callbackIntercept : original.callbackIntercept == null ? other.callbackIntercept : other.callbackIntercept.or(original.callbackIntercept);
    }

    private static <T> T getOrDefault(T value, T defVal) {
        return value != null ? value : defVal;
    }

    private static int getOrDefault(int value, int defVal) {
        return value != -1 ? value : defVal;
    }

    // test method

    Principal getPrincipal() {
        return forwardSecurityDomain != null ? forwardSecurityDomain.getCurrentSecurityIdentity().getPrincipal() : principal;
    }

    String getHost() {
        return setHost;
    }

    String getProtocol() {
        return setProtocol;
    }

    int getPort() {
        return setPort;
    }

    // internal actions

    /**
     * Determine if this SASL mechanism is supported by this configuration (not policy).  Implementations must
     * combine using boolean-OR operations.
     *
     * @param mechanismName the mech name (must not be {@code null})
     * @return {@code true} if supported, {@code false} otherwise
     */
    boolean saslSupportedByConfiguration(String mechanismName) {
        // if we have a credential-providing callback handler, we support any mechanism
        if (userCallbackKinds.contains(CallbackKind.CREDENTIAL)) {
            return true;
        }
        // if we have a key manager factory, we definitely support IEC/ISO 9798
        if (keyManagerFactory != null && SaslMechanismInformation.IEC_ISO_9798.test(mechanismName)) {
            return true;
        }
        // if a mechanism was explicitly allowed, we support it no matter what
        if (allowedSasl.contains(mechanismName)) {
            return true;
        }
        // otherwise, use mechanism information and our credential set
        Set<Class<? extends Credential>> types = SaslMechanismInformation.getSupportedClientCredentialTypes(mechanismName);
        final CredentialSource credentials = credentialSource;
        for (Class<? extends Credential> type : types) {
            if (AlgorithmCredential.class.isAssignableFrom(type)) {
                Set<String> algorithms = SaslMechanismInformation.getSupportedClientCredentialAlgorithms(mechanismName, type);
                if (algorithms.contains("*")) {
                    try {
                        if (credentials.getCredentialAcquireSupport(type, null).mayBeSupported()) {
                            return true;
                        }
                    } catch (IOException e) {
                        // no match
                    }
                } else {
                    for (String algorithm : algorithms) {
                        try {
                            if (credentials.getCredentialAcquireSupport(type, algorithm).mayBeSupported()) {
                                return true;
                            }
                        } catch (IOException e) {
                            // no match
                        }
                    }
                }
            } else {
                try {
                    if (credentials.getCredentialAcquireSupport(type).mayBeSupported()) {
                        return true;
                    }
                } catch (IOException e) {
                    // no match
                }
            }
        }
        // TODO: this is probably still wrong; revisit
        return mechanismName.equals(LocalUserSaslFactory.JBOSS_LOCAL_USER);
    }

    /**
     * Determine if this SASL mechanism is allowed by this configuration's policy.  Implementations must combine
     * using boolean-AND operations.
     *
     * @param mechanismName the mech name (must not be {@code null})
     * @return {@code true} if allowed, {@code false} otherwise
     */
    boolean saslAllowedByConfiguration(String mechanismName) {
        return ! deniedSasl.contains(mechanismName);
    }

    boolean filterOneSaslMechanism(String mechanismName) {
        return saslSupportedByConfiguration(mechanismName) && saslAllowedByConfiguration(mechanismName);
    }

    Principal doRewriteUser(Principal original) {
        final Function<Principal, Principal> principalRewriter = this.principalRewriter;
        final Principal rewritten = principalRewriter == null ? original : principalRewriter.apply(original);
        if (rewritten == null) {
            throw log.invalidName();
        }
        return rewritten;
    }

    String getAuthorizationName() {
        return setAuthzName;
    }

    Supplier<Provider[]> getProviderSupplier() {
        final Supplier<Provider[]> providerSupplier = this.providerSupplier;
        return providerSupplier == null ? Security::getProviders : providerSupplier;
    }

    SaslClientFactory getSaslClientFactory(Supplier<Provider[]> providers) {
        final Supplier<SaslClientFactory> supplier = saslClientFactorySupplier;
        return supplier != null ? supplier.get() : new SecurityProviderSaslClientFactory(providers);
    }

    SecurityFactory<X509TrustManager> getX509TrustManagerFactory() {
        return trustManagerFactory == null ? SSLUtils.getDefaultX509TrustManagerSecurityFactory() : trustManagerFactory;
    }

    SecurityFactory<X509KeyManager> getX509KeyManagerFactory() {
        return keyManagerFactory;
    }

    CredentialSource getCredentialSource() {
        if (forwardSecurityDomain != null) {
            return doPrivileged((PrivilegedAction<IdentityCredentials>) () -> forwardSecurityDomain.getCurrentSecurityIdentity().getPrivateCredentials(), capturedAccessContext);
        } else {
            return credentialSource;
        }
    }

    // assembly methods - rewrite

    /**
     * Create a new configuration which is the same as this configuration, but rewrites the user name using the given
     * name rewriter.  The name rewriter is appended to the the existing name rewrite function.
     *
     * @param rewriter the name rewriter
     * @return the new configuration
     */
    public AuthenticationConfiguration rewriteUser(NameRewriter rewriter) {
        if (rewriter == null) {
            return this;
        }
        return new AuthenticationConfiguration(this, SET_PRINCIPAL_RW, principalRewriter.andThen(rewriter.asPrincipalRewriter()));
    }

    /**
     * Create a new configuration which is the same as this configuration, but rewrites the user name using <em>only</em>
     * the given name rewriter.  Any name rewriters on this configuration are ignored for the new configuration.
     *
     * @param rewriter the name rewriter
     * @return the new configuration
     */
    public AuthenticationConfiguration rewriteUserOnlyWith(NameRewriter rewriter) {
        if (rewriter == null) {
            return this;
        }
        return new AuthenticationConfiguration(this, SET_PRINCIPAL_RW, rewriter.asPrincipalRewriter());
    }

    // assembly methods - filter

    // assembly methods - configuration

    /**
     * Create a new configuration which is the same as this configuration, but which uses an anonymous login.
     *
     * @return the new configuration
     */
    public AuthenticationConfiguration useAnonymous() {
        return usePrincipal(AnonymousPrincipal.getInstance());
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given principal to authenticate.
     *
     * @param principal the principal to use (must not be {@code null})
     * @return the new configuration
     */
    public AuthenticationConfiguration usePrincipal(NamePrincipal principal) {
        return usePrincipal((Principal) principal);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given principal to authenticate.
     *
     * @param principal the principal to use (must not be {@code null})
     * @return the new configuration
     */
    public AuthenticationConfiguration usePrincipal(Principal principal) {
        Assert.checkNotNullParam("principal", principal);
        if (Objects.equals(this.principal, principal)) {
            return this;
        }
        return new AuthenticationConfiguration(this, SET_PRINCIPAL, principal);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given login name to authenticate.
     *
     * @param name the principal to use (must not be {@code null})
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
        if (Objects.equals(name, setAuthzName)) {
            return this;
        } else {
            return new AuthenticationConfiguration(this, SET_AUTHZ_NAME, name);
        }
    }

    public AuthenticationConfiguration useCredential(Credential credential) {
        if (credential == null) return this;
        final CredentialSource credentialSource = this.credentialSource;
        if (credentialSource == CredentialSource.NONE) {
            return new AuthenticationConfiguration(this, SET_CRED_SOURCE, IdentityCredentials.NONE.withCredential(credential));
        } else if (credentialSource instanceof IdentityCredentials) {
            return new AuthenticationConfiguration(this, SET_CRED_SOURCE, ((IdentityCredentials) credentialSource).withCredential(credential));
        } else {
            return new AuthenticationConfiguration(this, SET_CRED_SOURCE, credentialSource.with(IdentityCredentials.NONE.withCredential(credential)));
        }
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @return the new configuration
     */
    public AuthenticationConfiguration usePassword(Password password) {
        final CredentialSource filtered = getCredentialSource().without(PasswordCredential.class);
        return password == null ? useCredentials(filtered) : useCredentials(filtered).useCredential(new PasswordCredential(password));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @return the new configuration
     */
    public AuthenticationConfiguration usePassword(char[] password) {
        return usePassword(password == null ? null : ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, password));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @return the new configuration
     */
    public AuthenticationConfiguration usePassword(String password) {
        return usePassword(password == null ? null : ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, password.toCharArray()));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given callback handler to
     * acquire a password with which to authenticate, when a password-based authentication algorithm is in use.
     *
     * @param callbackHandler the password callback handler
     * @return the new configuration
     */
    public AuthenticationConfiguration useCredentialCallbackHandler(CallbackHandler callbackHandler) {
        return useCallbackHandler(callbackHandler, EnumSet.of(CallbackKind.CREDENTIAL));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given callback handler
     * to authenticate.
     * <p>
     * <em>Important notes:</em> It is important to ensure that each distinct client identity uses a distinct {@code CallbackHandler}
     * instance in order to avoid mis-pooling of connections, identity crossovers, and other potentially serious problems.
     * It is not recommended that a {@code CallbackHandler} implement {@code equals()} and {@code hashCode()}, however if it does,
     * it is important to ensure that these methods consider equality based on an authenticating identity that does not
     * change between instances.  In particular, a callback handler which requests user input on each usage is likely to cause
     * a problem if the user name can change on each authentication request.
     * <p>
     * Because {@code CallbackHandler} instances are unique per identity, it is often useful for instances to cache
     * identity information, credentials, and/or other authentication-related information in order to facilitate fast
     * re-authentication.
     *
     * @param callbackHandler the callback handler to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useCallbackHandler(CallbackHandler callbackHandler) {
        return callbackHandler == null ? this : new AuthenticationConfiguration(this, SET_USER_CBH, callbackHandler, SET_USER_CB_KINDS, EnumSet.allOf(CallbackKind.class));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given callback handler
     * to authenticate.
     * <p>
     * <em>Important notes:</em> It is important to ensure that each distinct client identity uses a distinct {@code CallbackHandler}
     * instance in order to avoid mis-pooling of connections, identity crossovers, and other potentially serious problems.
     * It is not recommended that a {@code CallbackHandler} implement {@code equals()} and {@code hashCode()}, however if it does,
     * it is important to ensure that these methods consider equality based on an authenticating identity that does not
     * change between instances.  In particular, a callback handler which requests user input on each usage is likely to cause
     * a problem if the user name can change on each authentication request.
     * <p>
     * Because {@code CallbackHandler} instances are unique per identity, it is often useful for instances to cache
     * identity information, credentials, and/or other authentication-related information in order to facilitate fast
     * re-authentication.
     *
     * @param callbackHandler the callback handler to use
     * @param callbackKinds the kinds of callbacks that the handler should use
     * @return the new configuration
     */
    public AuthenticationConfiguration useCallbackHandler(CallbackHandler callbackHandler, Set<CallbackKind> callbackKinds) {
        return callbackHandler == null ? this : new AuthenticationConfiguration(this, SET_USER_CBH, callbackHandler, SET_USER_CB_KINDS, EnumSet.copyOf(callbackKinds));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given GSS-API credential to authenticate.
     *
     * @param credential the GSS-API credential to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useGSSCredential(GSSCredential credential) {
        return credential == null ? this : useCredential(new GSSKerberosCredential(credential));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given key store and alias
     * to acquire the credential required for authentication.
     *
     * @param keyStoreEntry the key store entry to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useKeyStoreCredential(KeyStore.Entry keyStoreEntry) {
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
    public AuthenticationConfiguration useKeyStoreCredential(KeyStore keyStore, String alias) {
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
    public AuthenticationConfiguration useKeyStoreCredential(KeyStore keyStore, String alias, KeyStore.ProtectionParameter protectionParameter) {
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
    public AuthenticationConfiguration useCertificateCredential(PrivateKey privateKey, X509Certificate... certificateChain) {
        return certificateChain == null || certificateChain.length == 0 || privateKey == null ? this : useCertificateCredential(new X509CertificateChainPrivateCredential(privateKey, certificateChain));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given private key and X.509
     * certificate chain to authenticate.
     *
     * @param credential the credential containing the private key and certificate chain
     * @return the new configuration
     */
    public AuthenticationConfiguration useCertificateCredential(X509CertificateChainPrivateCredential credential) {
        return credential == null ? this : useCredential(credential);
    }

    /**
     * Create a new configuration which is the same as this configuration, but uses credentials found at the given
     * alias and credential store.
     *
     * @param credentialStore the credential store (must not be {@code null})
     * @param alias the alias within the store (must not be {@code null})
     * @return the new configuration
     */
    public AuthenticationConfiguration useCredentialStoreEntry(CredentialStore credentialStore, String alias) {
        Assert.checkNotNullParam("credentialStore", credentialStore);
        Assert.checkNotNullParam("alias", alias);
        CredentialStoreCredentialSource csCredentialSource = new CredentialStoreCredentialSource(credentialStore, alias);
        return useCredentials(getCredentialSource().with(csCredentialSource));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given key manager
     * to acquire the credential required for authentication.
     *
     * @param keyManager the key manager to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useKeyManagerCredential(X509KeyManager keyManager) {
        return new AuthenticationConfiguration(this, SET_KEY_MGR_FAC, new FixedSecurityFactory<>(keyManager));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given identity
     * credentials to acquire the credential required for authentication.
     *
     * @param credentials the credentials to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useCredentials(CredentialSource credentials) {
        return new AuthenticationConfiguration(this, SET_CRED_SOURCE, credentials == null ? CredentialSource.NONE : credentials);
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
        Assert.checkNotNullParam("matchPredicate", matchPredicate);
        Assert.checkNotNullParam("choice", choice);
        final Predicate<Callback> callbackIntercept = this.callbackIntercept;
        Predicate<Callback> newIntercept = cb -> {
            if (! (cb instanceof ChoiceCallback)) {
                return false;
            }
            final ChoiceCallback choiceCallback = (ChoiceCallback) cb;
            if (matchPredicate.test(choiceCallback.getClass(), choiceCallback.getPrompt())) {
                final String[] choices = choiceCallback.getChoices();
                final int choicesLength = choices.length;
                for (int i = 0; i < choicesLength; i++) {
                    if (choices[i].equals(choice)) {
                        choiceCallback.setSelectedIndex(i);
                        return true;
                    }
                }
            }
            return false;
        };
        if (callbackIntercept == null) {
            return new AuthenticationConfiguration(this, SET_CALLBACK_INTERCEPT, newIntercept);
        } else {
            return new AuthenticationConfiguration(this, SET_CALLBACK_INTERCEPT, newIntercept.or(callbackIntercept));
        }
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given parameter specification.
     *
     * @param parameterSpec the algorithm parameter specification to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useParameterSpec(AlgorithmParameterSpec parameterSpec) {
        if (parameterSpec == null) {
            return this;
        }
        final List<AlgorithmParameterSpec> specs = parameterSpecs;
        if (specs.isEmpty()) {
            return new AuthenticationConfiguration(this, SET_PARAM_SPECS, Collections.singletonList(parameterSpec));
        } else {
            ArrayList<AlgorithmParameterSpec> newList = new ArrayList<>();
            for (AlgorithmParameterSpec spec : specs) {
                if (spec.getClass() == parameterSpec.getClass()) continue;
                newList.add(spec);
            }
            if (newList.isEmpty()) {
                return new AuthenticationConfiguration(this, SET_PARAM_SPECS, Collections.singletonList(parameterSpec));
            } else {
                newList.add(parameterSpec);
                return new AuthenticationConfiguration(this, SET_PARAM_SPECS, newList);
            }
        }
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given trust manager
     * for trust verification.
     *
     * @param trustManager the trust manager to use or {@code null} if the default trust manager should be used
     * @return the new configuration
     */
    public AuthenticationConfiguration useTrustManager(X509TrustManager trustManager) {
        return trustManager == null ? new AuthenticationConfiguration(this, SET_TRUST_MGR_FAC, null) : new AuthenticationConfiguration(this, SET_TRUST_MGR_FAC, new FixedSecurityFactory<>(trustManager));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which connects to a different host name.
     *
     * @param hostName the host name to connect to
     * @return the new configuration
     */
    public AuthenticationConfiguration useHost(String hostName) {
        if (hostName == null || hostName.isEmpty()) {
            hostName = null;
        }
        if (Objects.equals(this.setHost, hostName)) {
            return this;
        } else {
            return new AuthenticationConfiguration(this, SET_HOST, hostName);
        }
    }

    /**
     * Create a new configuration which is the same as this configuration, but which specifies a different protocol to be passed to the authentication mechanisms.
     *
     * @param protocol the protocol to pass to the authentication mechanisms.
     * @return the new configuration
     */
    public AuthenticationConfiguration useProtocol(String protocol) {
        if (protocol == null || protocol.isEmpty()) {
            protocol = null;
        }
        if (Objects.equals(this.setProtocol, protocol)) {
            return this;
        } else {
            return new AuthenticationConfiguration(this, SET_PROTOCOL, protocol);
        }
    }

    /**
     * Create a new configuration which is the same as this configuration, but which connects to a different port.
     *
     * @param port the port to connect to, or -1 to not override the port
     * @return the new configuration
     */
    public AuthenticationConfiguration usePort(int port) {
        if (port < -1 || port > 65535) throw log.invalidPortNumber(port);
        if (port == setPort) return this;
        return new AuthenticationConfiguration(this, port);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which forwards the authentication name
     * and credentials from the current identity of the given security domain.
     *
     * @param securityDomain the security domain
     * @return the new configuration
     */
    public AuthenticationConfiguration useForwardedIdentity(SecurityDomain securityDomain) {
        if (Objects.equals(forwardSecurityDomain, securityDomain)) {
            return this;
        } else {
            return new AuthenticationConfiguration(this, SET_ACCESS_CTXT, securityDomain != null ? AccessController.getContext() : null, SET_FWD_DOMAIN, securityDomain);
        }
    }

    // Providers

    /**
     * Use the given security provider supplier to locate security implementations.
     *
     * @param providerSupplier the provider supplier
     * @return the new configuration
     */
    public AuthenticationConfiguration useProviders(Supplier<Provider[]> providerSupplier) {
        if (Objects.equals(this.providerSupplier, providerSupplier)) {
            return this;
        }
        return new AuthenticationConfiguration(this, SET_PROVIDER_SUPPLIER, providerSupplier);
    }

    /**
     * Use the system default security providers to locate security implementations.
     *
     * @return the new configuration
     */
    public AuthenticationConfiguration useDefaultProviders() {
        return useProviders(null);
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

    // SASL Mechanisms

    /**
     * Use a pre-existing {@link SaslClientFactory} instead of discovery.
     *
     * @param saslClientFactory the pre-existing {@link SaslClientFactory} to use.
     * @return the new configuration.
     */
    public AuthenticationConfiguration useSaslClientFactory(final SaslClientFactory saslClientFactory) {
        return useSaslClientFactory(() -> saslClientFactory);
    }

    /**
     * Use the given sasl client factory supplier to obtain the {@link SaslClientFactory} to use.
     *
     * @param saslClientFactory the sasl client factory supplier to use.
     * @return the new configuration.
     */
    public AuthenticationConfiguration useSaslClientFactory(final Supplier<SaslClientFactory> saslClientFactory) {
        return new AuthenticationConfiguration(this, SET_SASL_FAC_SUP, saslClientFactory);
    }

    /**
     * Use provider based discovery to load available {@link SaslClientFactory} implementations.
     *
     * @return the new configuration.
     */
    public AuthenticationConfiguration useSaslClientFactoryFromProviders() {
        return new AuthenticationConfiguration(this, SET_SASL_FAC_SUP, null);
    }

    // SASL Configuration

    /**
     * Create a new configuration which is the same as this configuration, but which sets the properties that will be passed to
     * the {@code SaslClientFactory} when the mechanism is created.
     *
     * @param mechanismProperties the properties to be passed to the {@code SaslClientFactory} to create the mechanism.
     * @return the new configuration.
     */
    public AuthenticationConfiguration useMechanismProperties(Map<String, String> mechanismProperties) {
        return mechanismProperties == null || mechanismProperties.isEmpty() ? this : new AuthenticationConfiguration(this, SET_MECH_PROPS, new HashMap<>(mechanismProperties));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which does not forbid any SASL mechanisms.
     *
     * @return the new configuration.
     */
    public AuthenticationConfiguration allowAllSaslMechanisms() {
        if (deniedSasl.isEmpty()) {
            return this;
        }
        return new AuthenticationConfiguration(this, SET_DENIED_SASL, Collections.emptySet());
    }

    private static <T> Set<T> optimizeSet(Set<T> orig) {
        if (orig.isEmpty()) return Collections.emptySet();
        if (orig.size() == 1) return Collections.singleton(orig.iterator().next());
        return orig;
    }

    /**
     * Create a new configuration which is the same as this configuration, but which explicitly allows only the given named mechanisms.
     * Any unlisted mechanisms will not be supported unless the configuration supports it.
     *
     * @param names the mechanism names
     * @return the new configuration
     */
    public AuthenticationConfiguration allowSaslMechanisms(String... names) {
        if (names == null || names.length == 0) {
            // clear out all explicitly-allowed names
            return new AuthenticationConfiguration(this, SET_ALLOWED_SASL, Collections.emptySet());
        }
        Set<String> newAllowedSasl = new HashSet<>(names.length);
        Collections.addAll(newAllowedSasl, names);
        newAllowedSasl.remove(null);
        newAllowedSasl = optimizeSet(newAllowedSasl);
        Set<String> newDeniedSasl = new HashSet<>(deniedSasl);
        newDeniedSasl.removeAll(newAllowedSasl);
        newDeniedSasl = optimizeSet(newDeniedSasl);
        return new AuthenticationConfiguration(this, SET_ALLOWED_SASL, newAllowedSasl, SET_DENIED_SASL, newDeniedSasl);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which forbids the given named mechanisms.
     *
     * @param names the mechanism names
     * @return the new configuration
     */
    public AuthenticationConfiguration forbidSaslMechanisms(String... names) {
        if (names == null || names.length == 0) {
            // clear out all explicitly-allowed names
            return new AuthenticationConfiguration(this, SET_DENIED_SASL, Collections.emptySet());
        }
        Set<String> newDeniedSasl = new HashSet<>(deniedSasl);
        Collections.addAll(newDeniedSasl, names);
        newDeniedSasl = optimizeSet(newDeniedSasl);
        Set<String> newAllowedSasl = new HashSet<>(names.length);
        newAllowedSasl.removeAll(newDeniedSasl);
        newAllowedSasl.remove(null);
        newAllowedSasl = optimizeSet(newAllowedSasl);
        return new AuthenticationConfiguration(this, SET_ALLOWED_SASL, newAllowedSasl, SET_DENIED_SASL, newDeniedSasl);
    }

    // other

    /**
     * Create a new configuration which is the same as this configuration, but uses the given realm for authentication.
     *
     * @param realm the realm to use, or {@code null} to accept the default realm always
     * @return the new configuration
     */
    public AuthenticationConfiguration useRealm(String realm) {
        if (Objects.equals(realm, this.setRealm)) {
            return this;
        } else {
            return new AuthenticationConfiguration(this, SET_REALM, realm);
        }
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given {@link BearerTokenCredential} to authenticate.
     *
     * @param credential the bearer token credential to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useBearerTokenCredential(BearerTokenCredential credential) {
        return credential == null ? this : useCredentials(getCredentialSource().with(IdentityCredentials.NONE.withCredential(credential)));
    }

    // merging

    /**
     * Create a new configuration which is the same as this configuration, but which adds or replaces every item in the
     * {@code other} configuration with that item, overwriting any corresponding such item in this configuration.
     *
     * @param other the other authentication configuration
     * @return the merged authentication configuration
     */
    public AuthenticationConfiguration with(AuthenticationConfiguration other) {
        return new AuthenticationConfiguration(this, other);
    }

    // client methods

    CallbackHandler getUserCallbackHandler() {
        return userCallbackHandler;
    }

    EnumSet<CallbackKind> getUserCallbackKinds() {
        return userCallbackKinds;
    }

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

    SaslClient createSaslClient(URI uri, Collection<String> serverMechanisms, UnaryOperator<SaslClientFactory> factoryOperator) throws SaslException {
        SaslClientFactory saslClientFactory = factoryOperator.apply(getSaslClientFactory());

        final Map<String, ?> mechanismProperties = this.mechanismProperties;
        if (! mechanismProperties.isEmpty()) {
            saslClientFactory = new PropertiesSaslClientFactory(saslClientFactory, new HashMap<>(mechanismProperties));
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

        return saslClientFactory.createSaslClient(serverMechanisms.toArray(NO_STRINGS),
                getAuthorizationName(), uri.getScheme(), uri.getHost(), Collections.emptyMap(), createCallbackHandler());
    }

    CallbackHandler createCallbackHandler() {
        return new ClientCallbackHandler(this);
    }

    // equality

    /**
     * Determine whether this configuration is equal to another object.  Two configurations are equal if they
     * apply the same items.
     *
     * @param obj the other object
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public boolean equals(final Object obj) {
        return obj instanceof AuthenticationConfiguration && equals((AuthenticationConfiguration) obj);
    }

    /**
     * Determine whether this configuration is equal to another object.  Two configurations are equal if they
     * apply the same items.
     *
     * @param other the other object
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public boolean equals(final AuthenticationConfiguration other) {
        return hashCode() == other.hashCode()
            && Objects.equals(capturedAccessContext, other.capturedAccessContext)
            && Objects.equals(principal, other.principal)
            && Objects.equals(setHost, other.setHost)
            && Objects.equals(setProtocol, other.setProtocol)
            && Objects.equals(setRealm, other.setRealm)
            && Objects.equals(setAuthzName, other.setAuthzName)
            && Objects.equals(forwardSecurityDomain, other.forwardSecurityDomain)
            && Objects.equals(userCallbackHandler, other.userCallbackHandler)
            && Objects.equals(userCallbackKinds, other.userCallbackKinds)
            && Objects.equals(credentialSource, other.credentialSource)
            && this.setPort == other.setPort
            && Objects.equals(providerSupplier, other.providerSupplier)
            && Objects.equals(keyManagerFactory, other.keyManagerFactory)
            && Objects.equals(allowedSasl, other.allowedSasl)
            && Objects.equals(deniedSasl, other.deniedSasl)
            && Objects.equals(principalRewriter, other.principalRewriter)
            && Objects.equals(saslClientFactorySupplier, other.saslClientFactorySupplier)
            && Objects.equals(parameterSpecs, other.parameterSpecs)
            && Objects.equals(trustManagerFactory, other.trustManagerFactory)
            && Objects.equals(mechanismProperties, other.mechanismProperties);
    }

    /**
     * Get the hash code of this authentication configuration.
     *
     * @return the hash code of this authentication configuration
     */
    public int hashCode() {
        int hashCode = this.hashCode;
        if (hashCode == 0) {
            hashCode = Objects.hash(
                capturedAccessContext, principal, setHost, setProtocol, setRealm, setAuthzName, forwardSecurityDomain, userCallbackHandler, credentialSource,
                providerSupplier, keyManagerFactory, allowedSasl, deniedSasl, principalRewriter, saslClientFactorySupplier, parameterSpecs, trustManagerFactory,
                mechanismProperties) * 19 + setPort;
            if (hashCode == 0) {
                hashCode = 1;
            }
            this.hashCode = hashCode;
        }
        return hashCode;
    }

    // String Representation

    @Override
    public String toString() {
        String toString = this.toString;
        if (toString == null) {
            StringBuilder b = new StringBuilder(64);
            b.append("AuthenticationConfiguration:");
            if (principal != null) b.append("principal=").append(principal).append(',');
            if (setAuthzName != null) b.append("authorization-id=").append(setAuthzName).append(',');
            if (setHost != null) b.append("set-host=").append(setHost).append(',');
            if (setProtocol != null) b.append("set-protocol=").append(setProtocol).append(',');
            if (setPort != -1) b.append("set-port=").append(setPort).append(',');
            if (setRealm != null) b.append("set-realm=").append(setRealm).append(',');
            if (forwardSecurityDomain != null) b.append("forwarding-authentication,");
            if (userCallbackHandler != null) b.append("user-callback-handler=").append(userCallbackHandler).append(',');
            if (! userCallbackKinds.isEmpty()) b.append("user-callback-kinds=").append(userCallbackKinds).append(',');
            if (credentialSource != null) b.append("credentials-present,");
            if (providerSupplier != null) b.append("providers-supplier=").append(providerSupplier).append(',');
            if (keyManagerFactory != null) b.append("key-manager-factory=").append(keyManagerFactory).append(',');
            if (! allowedSasl.isEmpty()) b.append("always-allowed-sasl-mechanisms=").append(allowedSasl).append(',');
            if (! deniedSasl.isEmpty()) b.append("always-denied-sasl-mechanisms=").append(deniedSasl).append(',');
            if (principalRewriter != null) b.append("principal-rewriter=").append(principalRewriter).append(',');
            if (saslClientFactorySupplier != null) b.append("sasl-client-factory-supplier=").append(saslClientFactorySupplier).append(',');
            if (! parameterSpecs.isEmpty()) b.append("parameter-specifications=").append(parameterSpecs).append(',');
            if (trustManagerFactory != null) b.append("trust-manager-factory=").append(trustManagerFactory).append(',');
            if (! mechanismProperties.isEmpty()) b.append("mechanism-properties=").append(mechanismProperties).append(',');
            b.setLength(b.length() - 1);
            return this.toString = b.toString();
        }
        return toString;
    }

    // delegates for equality tests

    // interfaces

    static class ClientCallbackHandler implements CallbackHandler {
        private final AuthenticationConfiguration config;
        private final CallbackHandler userCallbackHandler;
        private List<TrustedAuthority> trustedAuthorities;

        ClientCallbackHandler(final AuthenticationConfiguration config) {
            this.config = config;
            userCallbackHandler = config.getUserCallbackHandler();
        }

        @SuppressWarnings("UnnecessaryContinue")
        public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            final AuthenticationConfiguration config = this.config;
            final Predicate<Callback> callbackIntercept = config.callbackIntercept;
            final ArrayList<Callback> userCallbacks = new ArrayList<>(callbacks.length);
            for (final Callback callback : callbacks) {
                if (callbackIntercept != null && callbackIntercept.test(callback)) {
                    continue;
                } else if (callback instanceof NameCallback) {
                    if (config.getUserCallbackKinds().contains(CallbackKind.PRINCIPAL)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    final NameCallback nameCallback = (NameCallback) callback;
                    // populate with our authentication name
                    final Principal principal = config.getPrincipal();
                    if (principal == null) {
                        final String defaultName = nameCallback.getDefaultName();
                        if (defaultName == null) {
                            CallbackUtil.unsupported(nameCallback);
                            continue;
                        }
                        nameCallback.setName(defaultName);
                        continue;
                    } else {
                        nameCallback.setName(config.doRewriteUser(principal).getName());
                        continue;
                    }
                } else if (callback instanceof PasswordCallback) {
                    if (config.getUserCallbackKinds().contains(CallbackKind.CREDENTIAL)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    final PasswordCallback passwordCallback = (PasswordCallback) callback;
                    final CredentialSource credentials = config.getCredentialSource();
                    if (credentials != null) {
                        final TwoWayPassword password = credentials.applyToCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, c -> c.getPassword(TwoWayPassword.class));
                        if (password instanceof ClearPassword) {
                            // shortcut
                            passwordCallback.setPassword(((ClearPassword) password).getPassword());
                            continue;
                        } else if (password != null) try {
                            PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm());
                            ClearPasswordSpec clearPasswordSpec = passwordFactory.getKeySpec(passwordFactory.translate(password), ClearPasswordSpec.class);
                            passwordCallback.setPassword(clearPasswordSpec.getEncodedPassword());
                            continue;
                        } catch (GeneralSecurityException e) {
                            // not supported
                            CallbackUtil.unsupported(passwordCallback);
                            continue;
                        }
                        else {
                            // supported but no credentials
                            continue;
                        }
                    } else {
                        // supported but no credentials
                        continue;
                    }
                } else if (callback instanceof PasswordResetCallback) {
                    if (config.getUserCallbackKinds().contains(CallbackKind.CREDENTIAL_RESET)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    // not supported
                    CallbackUtil.unsupported(callback);
                    continue;
                } else if (callback instanceof CredentialCallback) {
                    if (config.getUserCallbackKinds().contains(CallbackKind.CREDENTIAL)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    final CredentialCallback credentialCallback = (CredentialCallback) callback;
                    // special handling for X.509 when a key manager factory is set
                    final SecurityFactory<X509KeyManager> keyManagerFactory = config.getX509KeyManagerFactory();
                    if (keyManagerFactory != null) {
                        final String allowedAlgorithm = credentialCallback.getAlgorithm();
                        if (allowedAlgorithm != null && credentialCallback.isCredentialTypeSupported(X509CertificateChainPrivateCredential.class, allowedAlgorithm)) {
                            final X509KeyManager keyManager;
                            try {
                                keyManager = keyManagerFactory.create();
                            } catch (GeneralSecurityException e) {
                                throw log.unableToCreateKeyManager(e);
                            }
                            Principal[] acceptableIssuers;
                            if (trustedAuthorities != null) {
                                List<Principal> issuers = new ArrayList<Principal>();
                                for (TrustedAuthority trustedAuthority : trustedAuthorities) {
                                    if (trustedAuthority instanceof TrustedAuthority.CertificateTrustedAuthority) {
                                        final X509Certificate authorityCertificate = ((TrustedAuthority.CertificateTrustedAuthority) trustedAuthority).getIdentifier();
                                        issuers.add(authorityCertificate.getSubjectX500Principal());
                                    } else if (trustedAuthority instanceof TrustedAuthority.NameTrustedAuthority) {
                                        final String authorityName = ((TrustedAuthority.NameTrustedAuthority) trustedAuthority).getIdentifier();
                                        issuers.add(new X500Principal(authorityName));
                                    }
                                }
                                acceptableIssuers = issuers.toArray(NO_PRINCIPALS);
                            } else {
                                acceptableIssuers = null;
                            }
                            final String alias = keyManager.chooseClientAlias(new String[] { allowedAlgorithm }, acceptableIssuers, null);
                            if (alias != null) {
                                final X509Certificate[] certificateChain = keyManager.getCertificateChain(alias);
                                final PrivateKey privateKey = keyManager.getPrivateKey(alias);
                                credentialCallback.setCredential(new X509CertificateChainPrivateCredential(privateKey, certificateChain));
                                continue;
                            }
                            // otherwise fall out to normal handling
                        }
                    }
                    // normal handling
                    final Credential credential = config.getCredentialSource().getCredential(credentialCallback.getCredentialType(), credentialCallback.getAlgorithm(), credentialCallback.getParameterSpec());
                    if (credential != null && credentialCallback.isCredentialSupported(credential)) {
                        credentialCallback.setCredential(credential);
                        continue;
                    } else {
                        // supported but no credentials
                        continue;
                    }
                } else if (callback instanceof RealmChoiceCallback) {
                    if (config.getUserCallbackKinds().contains(CallbackKind.REALM)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    final RealmChoiceCallback realmChoiceCallback = (RealmChoiceCallback) callback;
                    // find our realm
                    final String realm = config.setRealm;
                    if (realm == null) {
                        realmChoiceCallback.setSelectedIndex(realmChoiceCallback.getDefaultChoice());
                        continue;
                    } else {
                        String[] choices = realmChoiceCallback.getChoices();
                        for (int i = 0; i < choices.length; i++) {
                            if (realm.equals(choices[i])) {
                                realmChoiceCallback.setSelectedIndex(i);
                                break;
                            }
                        }
                        // no choice matches, so just fall out and choose nothing
                        continue;
                    }
                } else if (callback instanceof RealmCallback) {
                    if (config.getUserCallbackKinds().contains(CallbackKind.REALM)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    RealmCallback realmCallback = (RealmCallback) callback;
                    final String realm = config.setRealm;
                    realmCallback.setText(realm != null ? realm : realmCallback.getDefaultText());
                    continue;
                } else if (callback instanceof ParameterCallback) {
                    if (config.getUserCallbackKinds().contains(CallbackKind.PARAMETERS)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    ParameterCallback parameterCallback = (ParameterCallback) callback;
                    if (parameterCallback.getParameterSpec() == null) {
                        for (AlgorithmParameterSpec parameterSpec : config.parameterSpecs) {
                            if (parameterCallback.isParameterSupported(parameterSpec)) {
                                parameterCallback.setParameterSpec(parameterSpec);
                                break; // inner loop break
                            }
                        }
                    }
                    continue;
                } else if (callback instanceof ChoiceCallback) { // Must come AFTER RealmChoiceCallback
                    if (config.getUserCallbackKinds().contains(CallbackKind.CHOICE)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    final ChoiceCallback choiceCallback = (ChoiceCallback) callback;
                    choiceCallback.setSelectedIndex(choiceCallback.getDefaultChoice());
                    continue;
                } else if (callback instanceof TrustedAuthoritiesCallback) {
                    if (config.getUserCallbackKinds().contains(CallbackKind.SERVER_TRUSTED_AUTHORITIES)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    final TrustedAuthoritiesCallback trustedAuthoritiesCallback = (TrustedAuthoritiesCallback) callback;
                    if (trustedAuthorities == null) {
                        trustedAuthorities = new ArrayList<>(trustedAuthoritiesCallback.getTrustedAuthorities());
                    } else {
                        final List<TrustedAuthority> authorities = new ArrayList<>(trustedAuthoritiesCallback.getTrustedAuthorities());
                        authorities.removeIf(trustedAuthorities::contains);
                        trustedAuthorities.addAll(authorities);
                    }
                    continue;
                } else if (callback instanceof EvidenceVerifyCallback) {
                    if (config.getUserCallbackKinds().contains(CallbackKind.PEER_CREDENTIAL)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    final EvidenceVerifyCallback evidenceVerifyCallback = (EvidenceVerifyCallback) callback;
                    // special handling for X.509
                    final SecurityFactory<X509TrustManager> trustManagerFactory = config.getX509TrustManagerFactory();
                    if (trustManagerFactory != null) {
                        final X509PeerCertificateChainEvidence peerCertificateChainEvidence = evidenceVerifyCallback.getEvidence(X509PeerCertificateChainEvidence.class);
                        if (peerCertificateChainEvidence != null) {
                            X509TrustManager trustManager;
                            try {
                                trustManager = trustManagerFactory.create();
                            } catch (GeneralSecurityException e) {
                                throw log.unableToCreateTrustManager(e);
                            }
                            try {
                                trustManager.checkServerTrusted(peerCertificateChainEvidence.getPeerCertificateChain(), peerCertificateChainEvidence.getAlgorithm());
                                evidenceVerifyCallback.setVerified(true);
                            } catch (CertificateException e) {
                            }
                            continue;
                        }
                    }
                    continue;
                } else if (callback instanceof TextOutputCallback) {
                    if (config.getUserCallbackKinds().contains(CallbackKind.GENERAL_OUTPUT)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    // ignore
                    continue;
                } else if (callback instanceof TextInputCallback) { // must come after RealmCallback
                    if (config.getUserCallbackKinds().contains(CallbackKind.GENERAL_INPUT)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    // always choose the default
                    final TextInputCallback inputCallback = (TextInputCallback) callback;
                    final String text = inputCallback.getText();
                    if (text == null) {
                        final String defaultText = inputCallback.getDefaultText();
                        if (defaultText != null) {
                            inputCallback.setText(defaultText);
                        } else {
                            CallbackUtil.unsupported(callback);
                            continue;
                        }
                    }
                    continue;
                } else {
                    CallbackUtil.unsupported(callback);
                    continue;
                }
            }
            if (! userCallbacks.isEmpty()) {
                // pass on to the user callback handler
                assert userCallbackHandler != null; // otherwise userCallbacks would be empty
                final Callback[] userCallbackArray = userCallbacks.toArray(NO_CALLBACKS);
                userCallbackHandler.handle(userCallbackArray);
            }
        }
    }
}
