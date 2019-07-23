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
import static java.security.AccessController.getContext;
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.util.ProviderUtil.INSTALLED_PROVIDERS;

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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

import javax.net.ssl.SSLSession;
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
import org.ietf.jgss.Oid;
import org.wildfly.common.Assert;
import org.wildfly.common.annotation.NotNull;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.ParameterCallback;
import org.wildfly.security.auth.callback.PasswordResetCallback;
import org.wildfly.security.auth.callback.SSLCallback;
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
import org.wildfly.security.credential.source.FactoryCredentialSource;
import org.wildfly.security.credential.source.KeyStoreCredentialSource;
import org.wildfly.security.credential.source.LocalKerberosCredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.manager.WildFlySecurityManager;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.localuser.LocalUserClient;
import org.wildfly.security.sasl.localuser.LocalUserSaslFactory;
import org.wildfly.security.sasl.util.FilterMechanismSaslClientFactory;
import org.wildfly.security.sasl.util.LocalPrincipalSaslClientFactory;
import org.wildfly.security.sasl.util.PrivilegedSaslClientFactory;
import org.wildfly.security.sasl.util.PropertiesSaslClientFactory;
import org.wildfly.security.sasl.util.ProtocolSaslClientFactory;
import org.wildfly.security.sasl.util.SSLSaslClientFactory;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.sasl.util.SecurityProviderSaslClientFactory;
import org.wildfly.security.sasl.util.ServerNameSaslClientFactory;
import org.wildfly.security.ssl.SSLConnection;
import org.wildfly.security.ssl.SSLUtils;
import org.wildfly.security.util.ProviderServiceLoaderSupplier;
import org.wildfly.security.util.ProviderUtil;
import org.wildfly.security.util._private.Arrays2;
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
    private static final int SET_AUTHZ_PRINCIPAL = 4;
    private static final int SET_FWD_AUTH_NAME_DOMAIN = 5;
    private static final int SET_USER_CBH = 6;
    private static final int SET_USER_CB_KINDS = 7;
    private static final int SET_CRED_SOURCE = 8;
    private static final int SET_PROVIDER_SUPPLIER = 9;
    private static final int SET_KEY_MGR_FAC = 10;
    private static final int SET_SASL_SELECTOR = 11;
    private static final int SET_FWD_AUTH_CRED_DOMAIN = 12;
    private static final int SET_PRINCIPAL_RW = 13;
    private static final int SET_SASL_FAC_SUP = 14;
    private static final int SET_PARAM_SPECS = 15;
    private static final int SET_TRUST_MGR_FAC = 16;
    private static final int SET_SASL_MECH_PROPS = 17;
    private static final int SET_ACCESS_CTXT = 18;
    private static final int SET_CALLBACK_INTERCEPT = 19;
    private static final int SET_SASL_PROTOCOL = 20;
    private static final int SET_FWD_AUTHZ_NAME_DOMAIN = 21;

    private static final Supplier<Provider[]> DEFAULT_PROVIDER_SUPPLIER = ProviderUtil.aggregate(
            () -> new Provider[] {
                    WildFlySecurityManager.isChecking() ?
                            AccessController.doPrivileged((PrivilegedAction<WildFlyElytronProvider>) () -> new WildFlyElytronProvider()) :
                            new WildFlyElytronProvider()
            },
            WildFlySecurityManager.isChecking() ?
                    AccessController.doPrivileged((PrivilegedAction<ProviderServiceLoaderSupplier>) () -> new ProviderServiceLoaderSupplier(AuthenticationConfiguration.class.getClassLoader(), true)) :
                    new ProviderServiceLoaderSupplier(AuthenticationConfiguration.class.getClassLoader(), true),
            INSTALLED_PROVIDERS);

    /**
     * An empty configuration which can be used as the basis for any configuration.  This configuration supports no
     * remapping of any kind, and always uses an anonymous principal.
     * @deprecated to obtain empty configuration use {@link #empty()} method instead
     */
    @Deprecated
    public static final AuthenticationConfiguration EMPTY = new AuthenticationConfiguration();

    /**
     * An empty configuration which can be used as the basis for any configuration.  This configuration supports no
     * remapping of any kind, and always uses an anonymous principal.
     */
    public static AuthenticationConfiguration empty() {
        return EMPTY;
    }

    private volatile SaslClientFactory saslClientFactory = null;
    private int hashCode;
    private String toString;

    final AccessControlContext capturedAccessContext;
    @NotNull final Principal principal;
    final String setHost;
    final String setProtocol;
    final String setRealm;
    final Principal setAuthzPrincipal;
    final SecurityDomain authenticationNameForwardSecurityDomain;
    final SecurityDomain authenticationCredentialsForwardSecurityDomain;
    final SecurityDomain authorizationNameForwardSecurityDomain;
    final CallbackHandler userCallbackHandler;
    final EnumSet<CallbackKind> userCallbackKinds;
    final CredentialSource credentialSource;
    final int setPort;
    final Supplier<Provider[]> providerSupplier;
    final SecurityFactory<X509KeyManager> keyManagerFactory;
    final SaslMechanismSelector saslMechanismSelector;
    final Function<Principal, Principal> principalRewriter;
    final Supplier<SaslClientFactory> saslClientFactorySupplier;
    final List<AlgorithmParameterSpec> parameterSpecs;
    final SecurityFactory<X509TrustManager> trustManagerFactory;
    final Map<String, ?> saslMechanismProperties;
    final Predicate<Callback> callbackIntercept;
    final String saslProtocol;

    // constructors

    /**
     * Construct the empty configuration instance.
     */
    private AuthenticationConfiguration() {
        this.capturedAccessContext = null;
        this.principal = AnonymousPrincipal.getInstance();
        this.setHost = null;
        this.setProtocol = null;
        this.setRealm = null;
        this.setAuthzPrincipal = null;
        this.authenticationNameForwardSecurityDomain = null;
        this.authenticationCredentialsForwardSecurityDomain = null;
        this.authorizationNameForwardSecurityDomain = null;
        this.userCallbackHandler = null;
        this.userCallbackKinds = NO_CALLBACK_KINDS;
        this.credentialSource = IdentityCredentials.NONE;
        this.setPort = -1;
        this.providerSupplier = DEFAULT_PROVIDER_SUPPLIER;
        this.keyManagerFactory = null;
        this.saslMechanismSelector = null;
        this.principalRewriter = null;
        this.saslClientFactorySupplier = null;
        this.parameterSpecs = Collections.emptyList();
        this.trustManagerFactory = null;
        this.saslMechanismProperties = Collections.singletonMap(LocalUserClient.QUIET_AUTH, "true");
        this.callbackIntercept = null;
        this.saslProtocol = null;
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
        this.setAuthzPrincipal = what == SET_AUTHZ_PRINCIPAL ? (Principal) value : original.setAuthzPrincipal;
        this.authenticationNameForwardSecurityDomain = what == SET_FWD_AUTH_NAME_DOMAIN ? (SecurityDomain) value : original.authenticationNameForwardSecurityDomain;
        this.authenticationCredentialsForwardSecurityDomain = what == SET_FWD_AUTH_CRED_DOMAIN ? (SecurityDomain) value : original.authenticationCredentialsForwardSecurityDomain;
        this.authorizationNameForwardSecurityDomain = what == SET_FWD_AUTHZ_NAME_DOMAIN ? (SecurityDomain) value : original.authorizationNameForwardSecurityDomain;
        this.userCallbackHandler = what == SET_USER_CBH ? (CallbackHandler) value : original.userCallbackHandler;
        this.userCallbackKinds = (what == SET_USER_CB_KINDS ? (EnumSet<CallbackKind>) value : original.userCallbackKinds).clone();
        this.credentialSource = what == SET_CRED_SOURCE ? (CredentialSource) value : original.credentialSource;
        this.setPort = original.setPort;
        this.providerSupplier = what == SET_PROVIDER_SUPPLIER ? (Supplier<Provider[]>) value : original.providerSupplier;
        this.keyManagerFactory = what == SET_KEY_MGR_FAC ? (SecurityFactory<X509KeyManager>) value : original.keyManagerFactory;
        this.saslMechanismSelector = what == SET_SASL_SELECTOR ? (SaslMechanismSelector) value : original.saslMechanismSelector;
        this.principalRewriter = what == SET_PRINCIPAL_RW ? (Function<Principal, Principal>) value : original.principalRewriter;
        this.saslClientFactorySupplier = what == SET_SASL_FAC_SUP ? (Supplier<SaslClientFactory>) value : original.saslClientFactorySupplier;
        this.parameterSpecs = what == SET_PARAM_SPECS ? (List<AlgorithmParameterSpec>) value : original.parameterSpecs;
        this.trustManagerFactory = what == SET_TRUST_MGR_FAC ? (SecurityFactory<X509TrustManager>) value : original.trustManagerFactory;
        this.saslMechanismProperties = what == SET_SASL_MECH_PROPS ? (Map<String, ?>) value : original.saslMechanismProperties;
        this.callbackIntercept = what == SET_CALLBACK_INTERCEPT ? (Predicate<Callback>) value : original.callbackIntercept;
        this.saslProtocol = what == SET_SASL_PROTOCOL ? (String) value : original.saslProtocol;
        sanitazeOnMutation(what);
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
        this.setAuthzPrincipal = what1 == SET_AUTHZ_PRINCIPAL ? (Principal) value1 : what2 == SET_AUTHZ_PRINCIPAL ? (Principal) value2 : original.setAuthzPrincipal;
        this.authenticationNameForwardSecurityDomain = what1 == SET_FWD_AUTH_NAME_DOMAIN ? (SecurityDomain) value1 : what2 == SET_FWD_AUTH_NAME_DOMAIN ? (SecurityDomain) value2 : original.authenticationNameForwardSecurityDomain;
        this.authenticationCredentialsForwardSecurityDomain = what1 == SET_FWD_AUTH_CRED_DOMAIN ? (SecurityDomain) value1 : what2 == SET_FWD_AUTH_CRED_DOMAIN ? (SecurityDomain) value2 : original.authenticationCredentialsForwardSecurityDomain;
        this.authorizationNameForwardSecurityDomain = what1 == SET_FWD_AUTHZ_NAME_DOMAIN ? (SecurityDomain) value1 : what2 == SET_FWD_AUTHZ_NAME_DOMAIN ? (SecurityDomain) value2 : original.authorizationNameForwardSecurityDomain;
        this.userCallbackHandler = what1 == SET_USER_CBH ? (CallbackHandler) value1 : what2 == SET_USER_CBH ? (CallbackHandler) value2 : original.userCallbackHandler;
        this.userCallbackKinds = (what1 == SET_USER_CB_KINDS ? (EnumSet<CallbackKind>) value1 : what2 == SET_USER_CB_KINDS ? (EnumSet<CallbackKind>) value2 : original.userCallbackKinds).clone();
        this.credentialSource = what1 == SET_CRED_SOURCE ? (CredentialSource) value1 : what2 == SET_CRED_SOURCE ? (CredentialSource) value2 : original.credentialSource;
        this.setPort = original.setPort;
        this.providerSupplier = what1 == SET_PROVIDER_SUPPLIER ? (Supplier<Provider[]>) value1 : what2 == SET_PROVIDER_SUPPLIER ? (Supplier<Provider[]>) value2 : original.providerSupplier;
        this.keyManagerFactory = what1 == SET_KEY_MGR_FAC ? (SecurityFactory<X509KeyManager>) value1 : what2 == SET_KEY_MGR_FAC ? (SecurityFactory<X509KeyManager>) value2 : original.keyManagerFactory;
        this.saslMechanismSelector = what1 == SET_SASL_SELECTOR ? (SaslMechanismSelector) value1 : what2 == SET_SASL_SELECTOR ? (SaslMechanismSelector) value2 : original.saslMechanismSelector;
        this.principalRewriter = what1 == SET_PRINCIPAL_RW ? (Function<Principal, Principal>) value1 : what2 == SET_PRINCIPAL_RW ? (Function<Principal, Principal>) value2 : original.principalRewriter;
        this.saslClientFactorySupplier = what1 == SET_SASL_FAC_SUP ? (Supplier<SaslClientFactory>) value1 : what2 == SET_SASL_FAC_SUP ? (Supplier<SaslClientFactory>) value2 : original.saslClientFactorySupplier;
        this.parameterSpecs = what1 == SET_PARAM_SPECS ? (List<AlgorithmParameterSpec>) value1 : what2 == SET_PARAM_SPECS ? (List<AlgorithmParameterSpec>) value2 : original.parameterSpecs;
        this.trustManagerFactory = what1 == SET_TRUST_MGR_FAC ? (SecurityFactory<X509TrustManager>) value1 : what2 == SET_TRUST_MGR_FAC ? (SecurityFactory<X509TrustManager>) value2 : original.trustManagerFactory;
        this.saslMechanismProperties = what1 == SET_SASL_MECH_PROPS ? (Map<String, ?>) value1 : what2 == SET_SASL_MECH_PROPS ? (Map<String, ?>) value2 : original.saslMechanismProperties;
        this.callbackIntercept = what1 == SET_CALLBACK_INTERCEPT ? (Predicate<Callback>) value1 : what2 == SET_CALLBACK_INTERCEPT ? (Predicate<Callback>) value2 : original.callbackIntercept;
        this.saslProtocol = what1 == SET_SASL_PROTOCOL ? (String) value1 : what2 == SET_SASL_PROTOCOL ? (String) value2 : original.saslProtocol;
        sanitazeOnMutation(what1);
        sanitazeOnMutation(what2);
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
        this.setAuthzPrincipal = original.setAuthzPrincipal;
        this.authenticationNameForwardSecurityDomain = original.authenticationNameForwardSecurityDomain;
        this.authenticationCredentialsForwardSecurityDomain = original.authenticationCredentialsForwardSecurityDomain;
        this.authorizationNameForwardSecurityDomain = original.authorizationNameForwardSecurityDomain;
        this.userCallbackHandler = original.userCallbackHandler;
        this.userCallbackKinds = original.userCallbackKinds;
        this.credentialSource = original.credentialSource;
        this.setPort = port;
        this.providerSupplier = original.providerSupplier;
        this.keyManagerFactory = original.keyManagerFactory;
        this.saslMechanismSelector = original.saslMechanismSelector;
        this.principalRewriter = original.principalRewriter;
        this.saslClientFactorySupplier = original.saslClientFactorySupplier;
        this.parameterSpecs = original.parameterSpecs;
        this.trustManagerFactory = original.trustManagerFactory;
        this.saslMechanismProperties = original.saslMechanismProperties;
        this.callbackIntercept = original.callbackIntercept;
        this.saslProtocol = original.saslProtocol;
    }

    private AuthenticationConfiguration(final AuthenticationConfiguration original, final AuthenticationConfiguration other) {
        this.capturedAccessContext = getOrDefault(other.capturedAccessContext, original.capturedAccessContext);
        this.principal = other.principal instanceof AnonymousPrincipal ? original.principal : other.principal;
        this.setHost = getOrDefault(other.setHost, original.setHost);
        this.setProtocol = getOrDefault(other.setProtocol, original.setProtocol);
        this.setRealm = getOrDefault(other.setRealm, original.setRealm);
        this.setAuthzPrincipal = getOrDefault(other.setAuthzPrincipal, original.setAuthzPrincipal);
        this.authenticationNameForwardSecurityDomain = getOrDefault(other.authenticationNameForwardSecurityDomain, original.authenticationNameForwardSecurityDomain);
        this.authenticationCredentialsForwardSecurityDomain = getOrDefault(other.authenticationCredentialsForwardSecurityDomain, original.authenticationCredentialsForwardSecurityDomain);
        this.authorizationNameForwardSecurityDomain = getOrDefault(other.authorizationNameForwardSecurityDomain, original.authorizationNameForwardSecurityDomain);
        this.userCallbackHandler = getOrDefault(other.userCallbackHandler, original.userCallbackHandler);
        this.userCallbackKinds = getOrDefault(other.userCallbackKinds, original.userCallbackKinds).clone();
        this.credentialSource = other.credentialSource == IdentityCredentials.NONE ? original.credentialSource : other.credentialSource;
        this.setPort = getOrDefault(other.setPort, original.setPort);
        this.providerSupplier = getOrDefault(other.providerSupplier, original.providerSupplier);
        this.keyManagerFactory = getOrDefault(other.keyManagerFactory, original.keyManagerFactory);
        this.saslMechanismSelector = getOrDefault(other.saslMechanismSelector, original.saslMechanismSelector);
        this.principalRewriter = getOrDefault(other.principalRewriter, original.principalRewriter);
        this.saslClientFactorySupplier = getOrDefault(other.saslClientFactorySupplier, original.saslClientFactorySupplier);
        this.parameterSpecs = getOrDefault(other.parameterSpecs, original.parameterSpecs);
        this.trustManagerFactory = getOrDefault(other.trustManagerFactory, original.trustManagerFactory);
        this.saslMechanismProperties = getOrDefault(other.saslMechanismProperties, original.saslMechanismProperties);
        this.callbackIntercept = other.callbackIntercept == null ? original.callbackIntercept : original.callbackIntercept == null ? other.callbackIntercept : other.callbackIntercept.or(original.callbackIntercept);
        this.saslProtocol =  getOrDefault(other.saslProtocol, original.saslProtocol);
        sanitazeOnMutation(SET_USER_CBH);
    }

    private static <T> T getOrDefault(T value, T defVal) {
        return value != null ? value : defVal;
    }

    private static int getOrDefault(int value, int defVal) {
        return value != -1 ? value : defVal;
    }

    // test method

    Principal getPrincipal() {
        return authenticationNameForwardSecurityDomain != null ? authenticationNameForwardSecurityDomain.getCurrentSecurityIdentity().getPrincipal() : principal;
    }

    @Deprecated
    String getHost() {
        return setHost;
    }

    @Deprecated
    String getProtocol() {
        return setProtocol;
    }

    String getSaslProtocol() {
        return saslProtocol;
    }

    @Deprecated
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
        // special case for local, quiet auth
        // anonymous is only supported if the principal is anonymous.  If the principal is anonymous, only anonymous or principal-less mechanisms are supported.
        if (! userCallbackKinds.contains(CallbackKind.PRINCIPAL) && principal != AnonymousPrincipal.getInstance()) {
            // no callback which can handle a principal.
            if (! (mechanismName.equals(LocalUserSaslFactory.JBOSS_LOCAL_USER) || SaslMechanismInformation.doesNotUsePrincipal(mechanismName))) {
                // the mechanism requires a principal.
                if (getPrincipal() instanceof AnonymousPrincipal != mechanismName.equals(SaslMechanismInformation.Names.ANONYMOUS)) {
                    // either we have no principal & the mech requires one, or we have a principal but the mech is anonymous.
                    return false;
                }
            }
        }
        // if we have a credential-providing callback handler, we support any mechanism from here on out
        if (userCallbackKinds.contains(CallbackKind.CREDENTIAL) || (credentialSource != null && ! credentialSource.equals(IdentityCredentials.NONE))) {
            return true;
        }
        // mechanisms that do not need credentials are probably supported
        if (SaslMechanismInformation.doesNotRequireClientCredentials(mechanismName)) {
            return true;
        }
        // if we have a key manager factory, we definitely support IEC/ISO 9798
        if (keyManagerFactory != null && SaslMechanismInformation.IEC_ISO_9798.test(mechanismName)) {
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
        // no apparent way to support the mechanism
        return false;
    }

    Principal doRewriteUser(Principal original) {
        final Function<Principal, Principal> principalRewriter = this.principalRewriter;
        final Principal rewritten = principalRewriter == null ? original : principalRewriter.apply(original);
        if (rewritten == null) {
            throw log.invalidName();
        }
        return rewritten;
    }

    Principal getAuthorizationPrincipal() {
        return authorizationNameForwardSecurityDomain != null ? authorizationNameForwardSecurityDomain.getCurrentSecurityIdentity().getPrincipal() : setAuthzPrincipal;
    }

    Supplier<Provider[]> getProviderSupplier() {
        final Supplier<Provider[]> providerSupplier = this.providerSupplier;
        return providerSupplier == null ? INSTALLED_PROVIDERS : providerSupplier;
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
        if (authenticationCredentialsForwardSecurityDomain != null) {
            return doPrivileged((PrivilegedAction<IdentityCredentials>) () -> authenticationCredentialsForwardSecurityDomain.getCurrentSecurityIdentity().getPrivateCredentials(), capturedAccessContext);
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

        if (this.principalRewriter == null) {
            return new AuthenticationConfiguration(this, SET_PRINCIPAL_RW, rewriter.asPrincipalRewriter());
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
        Assert.checkNotNullParam("name", name);
        return usePrincipal(new NamePrincipal(name));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which attempts to authorize to the given
     * name after authentication.  Only mechanisms which support an authorization name principal will be selected.
     *
     * @param name the name to use, or {@code null} to not request authorization in the new configuration
     * @return the new configuration
     */
    public AuthenticationConfiguration useAuthorizationName(String name) {
        return useAuthorizationPrincipal(name == null ? null : new NamePrincipal(name));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which attempts to authorize to the given
     * principal after authentication.  Only mechanisms which support an authorization principal of the given type will
     * be selected.
     *
     * @param principal the principal to use, or {@code null} to not request authorization in the new configuration
     * @return the new configuration
     */
    public AuthenticationConfiguration useAuthorizationPrincipal(Principal principal) {
        if (Objects.equals(principal, setAuthzPrincipal)) {
            return this;
        } else {
            return new AuthenticationConfiguration(this, SET_AUTHZ_PRINCIPAL, principal);
        }
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given credential to authenticate.
     *
     * @param credential the credential to authenticate
     * @return the new configuration
     */
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
     * Create a new configuration which is the same as this configuration, but which uses local kerberos ticket cache
     * to acquire the credential required for authentication.
     *
     * @param mechanismOids array of oid's indicating the mechanisms over which the credential is to be acquired
     * @return the new configuration
     *
     * @since 1.2.0
     * @deprecated can be ommited - kerberos based authentication mechanism obtains credential himself
     */
    @Deprecated
    public AuthenticationConfiguration useLocalKerberosCredential(Oid[] mechanismOids) {
        return useCredentials(getCredentialSource().with(LocalKerberosCredentialSource.builder().setMechanismOids(mechanismOids).build()));
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
     * @deprecated This configuration is not supported by most providers and will be removed in a future release.
     */
    @Deprecated
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
     * Create a new configuration which is the same as this configuration, but which specifies a different protocol to be used for outgoing connection.
     *
     * @param protocol the protocol to be used for outgoing connection.
     * @return the new configuration
     * @deprecated This configuration is not supported by most providers and will be removed in a future release.
     */
    @Deprecated
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
     * Create a new configuration which is the same as this configuration, but which specifies a different protocol to be passed to the authentication mechanisms.
     *
     * @param saslProtocol the protocol to pass to the authentication mechanisms.
     * @return the new configuration
     */
    public AuthenticationConfiguration useSaslProtocol(String saslProtocol) {
        if (saslProtocol == null || saslProtocol.isEmpty()) {
            saslProtocol = null;
        }
        if (Objects.equals(this.saslProtocol, saslProtocol)) {
            return this;
        } else {
            return new AuthenticationConfiguration(this, SET_SASL_PROTOCOL, saslProtocol);
        }
    }

    /**
     * Create a new configuration which is the same as this configuration, but which connects to a different port.
     *
     * @param port the port to connect to, or -1 to not override the port
     * @return the new configuration
     * @deprecated This configuration is not supported by most providers and will be removed in a future release.
     */
    @Deprecated
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
        return useForwardedAuthenticationIdentity(securityDomain).useForwardedAuthenticationCredentials(securityDomain);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which forwards the authentication name
     * from the current identity of the given security domain.
     *
     * @param securityDomain the security domain
     * @return the new configuration
     */
    public AuthenticationConfiguration useForwardedAuthenticationIdentity(SecurityDomain securityDomain) {
        if (Objects.equals(authenticationNameForwardSecurityDomain, securityDomain)) {
            return this;
        } else {
            return new AuthenticationConfiguration(this, SET_ACCESS_CTXT, securityDomain != null ? getContext() : null, SET_FWD_AUTH_NAME_DOMAIN, securityDomain);
        }
    }

    /**
     * Create a new configuration which is the same as this configuration, but which forwards the authentication
     * credentials from the current identity of the given security domain.
     *
     * @param securityDomain the security domain
     * @return the new configuration
     */
    public AuthenticationConfiguration useForwardedAuthenticationCredentials(SecurityDomain securityDomain) {
        if (Objects.equals(authenticationCredentialsForwardSecurityDomain, securityDomain)) {
            return this;
        } else {
            return new AuthenticationConfiguration(this, SET_ACCESS_CTXT, securityDomain != null ? getContext() : null, SET_FWD_AUTH_CRED_DOMAIN, securityDomain);
        }
    }

    /**
     * Create a new configuration which is the same as this configuration, but which forwards the authorization name
     * from the current identity of the given security domain.
     *
     * @param securityDomain the security domain
     * @return the new configuration
     */
    public AuthenticationConfiguration useForwardedAuthorizationIdentity(SecurityDomain securityDomain) {
        if (Objects.equals(authorizationNameForwardSecurityDomain, securityDomain)) {
            return this;
        } else {
            return new AuthenticationConfiguration(this, SET_ACCESS_CTXT, securityDomain != null ? getContext() : null, SET_FWD_AUTHZ_NAME_DOMAIN, securityDomain);
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
     * Use the default provider discovery behaviour of combining service loader discovered providers with the system default
     * security providers when locating security implementations.
     *
     * @return the new configuration
     */
    public AuthenticationConfiguration useDefaultProviders() {
        return useProviders(DEFAULT_PROVIDER_SUPPLIER);
    }

    /**
     * Use security providers from the given class loader.
     *
     * @param classLoader the class loader to search for security providers
     * @return the new configuration
     */
    public AuthenticationConfiguration useProvidersFromClassLoader(ClassLoader classLoader) {
        return useProviders(new ProviderServiceLoaderSupplier(classLoader));
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
     * Existing properties defined on this authentication context will be retained unless overridden by new properties, any
     * properties resulting with a value of {@code null} will be removed.
     *
     * @param mechanismProperties the properties to be passed to the {@code SaslClientFactory} to create the mechanism.
     * @return the new configuration.
     * @deprecated use {@link #useSaslMechanismProperties(Map)}
     */
    @Deprecated
    public AuthenticationConfiguration useMechanismProperties(Map<String, ?> mechanismProperties) {
        return useSaslMechanismProperties(mechanismProperties);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which sets the properties that will be passed to
     * the {@code SaslClientFactory} when the mechanism is created.
     *
     * Existing properties defined on this authentication context will be retained unless overridden by new properties, any
     * properties resulting with a value of {@code null} will be removed.
     *
     * @param mechanismProperties the properties to be passed to the {@code SaslClientFactory} to create the mechanism.
     * @return the new configuration.
     */
    public AuthenticationConfiguration useSaslMechanismProperties(Map<String, ?> mechanismProperties) {
        return useSaslMechanismProperties(mechanismProperties, false);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which sets the properties that will be passed to
     * the {@code SaslClientFactory} when the mechanism is created.
     *
     * If exclusive the existing properties will be discarded and replaced with the new properties otherwise existing properties
     * defined on this authentication context will be retained unless overridden by new properties, any properties resulting
     * with a value of {@code null} will be removed.
     *
     * @param mechanismProperties the properties to be passed to the {@code SaslClientFactory} to create the mechanism.
     * @param exclusive should the provided properties be used exclusively or merged with the existing properties?
     * @return the new configuration.
     * @deprecated use {@link #useSaslMechanismProperties(Map, boolean)}
     */
    @Deprecated
    public AuthenticationConfiguration useMechanismProperties(Map<String, ?> mechanismProperties, boolean exclusive) {
        return useSaslMechanismProperties(mechanismProperties, exclusive);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which sets the properties that will be passed to
     * the {@code SaslClientFactory} when the mechanism is created.
     *
     * If exclusive the existing properties will be discarded and replaced with the new properties otherwise existing properties
     * defined on this authentication context will be retained unless overridden by new properties, any properties resulting
     * with a value of {@code null} will be removed.
     *
     * @param mechanismProperties the properties to be passed to the {@code SaslClientFactory} to create the mechanism.
     * @param exclusive should the provided properties be used exclusively or merged with the existing properties?
     * @return the new configuration.
     */
    public AuthenticationConfiguration useSaslMechanismProperties(Map<String, ?> mechanismProperties, boolean exclusive) {
        if (!exclusive && (mechanismProperties == null || mechanismProperties.isEmpty())) return this;
        final HashMap<String, Object> newMap = exclusive ? new HashMap<>() : new HashMap<>(this.saslMechanismProperties);
        newMap.putAll(mechanismProperties);
        newMap.values().removeIf(Objects::isNull);
        return new AuthenticationConfiguration(this, SET_SASL_MECH_PROPS, optimizeMap(newMap));
    }

    private static <K, V> Map<K, V> optimizeMap(Map<K, V> orig) {
        if (orig.isEmpty()) return Collections.emptyMap();
        if (orig.size() == 1) {
            final Map.Entry<K, V> entry = orig.entrySet().iterator().next();
            return Collections.singletonMap(entry.getKey(), entry.getValue());
        }
        return orig;
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given kerberos security
     * factory to acquire the GSS credential required for authentication.
     *
     * @param kerberosSecurityFactory a reference to the kerberos security factory to be use
     * @return the new configuration
     */
    @Deprecated
    public AuthenticationConfiguration useKerberosSecurityFactory(SecurityFactory<Credential> kerberosSecurityFactory) {
        CredentialSource cs = getCredentialSource();
        if (kerberosSecurityFactory != null) {
            return cs != null ? new AuthenticationConfiguration(this, SET_CRED_SOURCE, cs.with(new FactoryCredentialSource(kerberosSecurityFactory))) : new AuthenticationConfiguration(this, SET_CRED_SOURCE, new FactoryCredentialSource(kerberosSecurityFactory));
        }
        return this; // cs != null ? new AuthenticationConfiguration(this, SET_CRED_SOURCE, cs.without(GSSKerberosCredential.class)) : this;
    }

    /**
     * Set the SASL mechanism selector for this authentication configuration.
     *
     * @param saslMechanismSelector the SASL mechanism selector, or {@code null} to clear the current selector
     * @return the new configuration
     */
    public AuthenticationConfiguration setSaslMechanismSelector(SaslMechanismSelector saslMechanismSelector) {
        if (Objects.equals(this.saslMechanismSelector, saslMechanismSelector)) {
            return this;
        }
        return new AuthenticationConfiguration(this, SET_SASL_SELECTOR, saslMechanismSelector);
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

    /**
     * Create a new configuration which is the same as this configuration, but which captures the caller's access
     * control context to be used in authentication decisions.
     *
     * @return the new configuration
     */
    public AuthenticationConfiguration withCapturedAccessControlContext() {
        return new AuthenticationConfiguration(this, SET_ACCESS_CTXT, getContext());
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

    SaslClient createSaslClient(URI uri, Collection<String> serverMechanisms, UnaryOperator<SaslClientFactory> factoryOperator, SSLSession sslSession) throws SaslException {
        SaslClientFactory saslClientFactory = factoryOperator.apply(getSaslClientFactory());
        final SaslMechanismSelector selector = this.saslMechanismSelector;
        serverMechanisms = (selector == null ? SaslMechanismSelector.DEFAULT : selector).apply(serverMechanisms, sslSession);
        if (serverMechanisms.isEmpty()) {
            return null;
        }
        final Principal authorizationPrincipal = getAuthorizationPrincipal();
        final Predicate<String> filter;
        final String authzName;
        if (authorizationPrincipal == null) {
            filter = this::saslSupportedByConfiguration;
            authzName = null;
        } else if (authorizationPrincipal instanceof NamePrincipal) {
            filter = this::saslSupportedByConfiguration;
            authzName = authorizationPrincipal.getName();
        } else if (authorizationPrincipal instanceof AnonymousPrincipal) {
            filter = ((Predicate<String>) this::saslSupportedByConfiguration).and("ANONYMOUS"::equals);
            authzName = null;
        } else {
            return null;
        }
        Map<String, ?> mechanismProperties = this.saslMechanismProperties;
        if (! mechanismProperties.isEmpty()) {
            mechanismProperties = new HashMap<>(mechanismProperties);
            // special handling for JBOSS-LOCAL-USER quiet auth... only pass it through if we have a user callback
            if (! userCallbackKinds.contains(CallbackKind.PRINCIPAL) && principal != AnonymousPrincipal.getInstance()) {
                mechanismProperties.remove(LocalUserClient.QUIET_AUTH);
                mechanismProperties.remove(LocalUserClient.LEGACY_QUIET_AUTH);
            }
            if (! mechanismProperties.isEmpty()) {
                saslClientFactory = new PropertiesSaslClientFactory(saslClientFactory, mechanismProperties);
            }
        }
        String host = uri.getHost();
        if (host != null) {
            saslClientFactory = new ServerNameSaslClientFactory(saslClientFactory, host);
        }
        String protocol = getSaslProtocol();
        if (protocol != null) {
            saslClientFactory = new ProtocolSaslClientFactory(saslClientFactory, protocol);
        }
        if (sslSession != null) {
            saslClientFactory = new SSLSaslClientFactory(() -> SSLConnection.forSession(sslSession, true), saslClientFactory);
        }
        saslClientFactory = new LocalPrincipalSaslClientFactory(new FilterMechanismSaslClientFactory(saslClientFactory, filter));
        final SaslClientFactory finalSaslClientFactory = saslClientFactory;
        final boolean captureAccessControlContext = Boolean.parseBoolean(System.getProperty("wildfly.elytron.capture.access.control.context", "true"));
        saslClientFactory = captureAccessControlContext ? doPrivileged((PrivilegedAction<PrivilegedSaslClientFactory>) () -> new PrivilegedSaslClientFactory(finalSaslClientFactory), capturedAccessContext) :
                new PrivilegedSaslClientFactory(finalSaslClientFactory);

        SaslClient saslClient = saslClientFactory.createSaslClient(serverMechanisms.toArray(NO_STRINGS),
                authzName, uri.getScheme(), uri.getHost(), Collections.emptyMap(), createCallbackHandler());

        if (log.isTraceEnabled()) {
            log.tracef("Created SaslClient [%s] for mechanisms %s", saslClient, Arrays2.objectToString(serverMechanisms));
        }
        return saslClient;
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
            && Objects.equals(principal, other.principal)
            && Objects.equals(setHost, other.setHost)
            && Objects.equals(setProtocol, other.setProtocol)
            && Objects.equals(setRealm, other.setRealm)
            && Objects.equals(setAuthzPrincipal, other.setAuthzPrincipal)
            && Objects.equals(authenticationNameForwardSecurityDomain, other.authenticationNameForwardSecurityDomain)
            && Objects.equals(authenticationCredentialsForwardSecurityDomain, other.authenticationCredentialsForwardSecurityDomain)
            && Objects.equals(authorizationNameForwardSecurityDomain, other.authorizationNameForwardSecurityDomain)
            && Objects.equals(userCallbackHandler, other.userCallbackHandler)
            && Objects.equals(userCallbackKinds, other.userCallbackKinds)
            && Objects.equals(credentialSource, other.credentialSource)
            && this.setPort == other.setPort
            && Objects.equals(providerSupplier, other.providerSupplier)
            && Objects.equals(keyManagerFactory, other.keyManagerFactory)
            && Objects.equals(saslMechanismSelector, other.saslMechanismSelector)
            && Objects.equals(principalRewriter, other.principalRewriter)
            && Objects.equals(saslClientFactorySupplier, other.saslClientFactorySupplier)
            && Objects.equals(parameterSpecs, other.parameterSpecs)
            && Objects.equals(trustManagerFactory, other.trustManagerFactory)
            && Objects.equals(saslMechanismProperties, other.saslMechanismProperties)
            && Objects.equals(saslProtocol, other.saslProtocol);
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
                principal, setHost, setProtocol, setRealm, setAuthzPrincipal, authenticationNameForwardSecurityDomain,
                authenticationCredentialsForwardSecurityDomain, authorizationNameForwardSecurityDomain, userCallbackHandler, credentialSource,
                providerSupplier, keyManagerFactory, saslMechanismSelector, principalRewriter, saslClientFactorySupplier, parameterSpecs, trustManagerFactory,
                saslMechanismProperties, saslProtocol) * 19 + setPort;
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
            b.append("principal=").append(principal).append(',');
            if (setAuthzPrincipal != null) b.append("authorization-id=").append(setAuthzPrincipal).append(',');
            if (setHost != null) b.append("set-host=").append(setHost).append(',');
            if (setProtocol != null) b.append("set-protocol=").append(setProtocol).append(',');
            if (saslProtocol != null) b.append("sasl-protocol-name=").append(saslProtocol).append(',');
            if (setPort != -1) b.append("set-port=").append(setPort).append(',');
            if (setRealm != null) b.append("set-realm=").append(setRealm).append(',');
            if (authenticationNameForwardSecurityDomain != null) b.append("forwarding-authentication-name,");
            if (authenticationCredentialsForwardSecurityDomain != null) b.append("forwarding-authentication-credentials,");
            if (authorizationNameForwardSecurityDomain != null) b.append("forwarding-authorization-name,");
            if (userCallbackHandler != null) b.append("user-callback-handler=").append(userCallbackHandler).append(',');
            if (! userCallbackKinds.isEmpty()) b.append("user-callback-kinds=").append(userCallbackKinds).append(',');
            if (credentialSource != null && credentialSource != CredentialSource.NONE && credentialSource != IdentityCredentials.NONE) b.append("credentials-present,");
            if (providerSupplier != null) b.append("providers-supplier=").append(providerSupplier).append(',');
            if (keyManagerFactory != null) b.append("key-manager-factory=").append(keyManagerFactory).append(',');
            if (saslMechanismSelector != null) b.append("sasl-mechanism-selector=").append(saslMechanismSelector).append(',');
            if (principalRewriter != null) b.append("principal-rewriter=").append(principalRewriter).append(',');
            if (saslClientFactorySupplier != null) b.append("sasl-client-factory-supplier=").append(saslClientFactorySupplier).append(',');
            if (! parameterSpecs.isEmpty()) b.append("parameter-specifications=").append(parameterSpecs).append(',');
            if (trustManagerFactory != null) b.append("trust-manager-factory=").append(trustManagerFactory).append(',');
            if (! saslMechanismProperties.isEmpty()) b.append("mechanism-properties=").append(saslMechanismProperties).append(',');
            b.setLength(b.length() - 1);
            return this.toString = b.toString();
        }
        return toString;
    }
    //user callback sanitation
    private void sanitazeOnMutation(final int what) {
        switch (what) {
            case SET_PRINCIPAL:
                // CallbackKind.PRINCIPAL
                if (this.principal != null && ! this.principal.equals(AnonymousPrincipal.getInstance())) {
                    this.userCallbackKinds.remove(CallbackKind.PRINCIPAL);
                }
                break;
            case SET_CRED_SOURCE:
                // CallbackKind.CREDENTIAL
                if (this.credentialSource != null && ! this.credentialSource.equals(IdentityCredentials.NONE)) {
                    this.userCallbackKinds.remove(CallbackKind.CREDENTIAL);
                }
                break;
            case SET_REALM:
                // CallbackKind.REALM
                this.userCallbackKinds.remove(CallbackKind.REALM);
                break;
            case SET_PARAM_SPECS:
                // CallbackKind.PARAMETERS
                this.userCallbackKinds.remove(CallbackKind.PARAMETERS);
                break;
            case SET_KEY_MGR_FAC:
                // CallbackKind.PEER_CREDENTIAL
                this.userCallbackKinds.remove(CallbackKind.PEER_CREDENTIAL);
                break;
            case SET_USER_CB_KINDS:
                // SANITAZE on above content
                if (this.principal != null) {
                    sanitazeOnMutation(SET_PRINCIPAL);
                }

                if (this.credentialSource != null) {
                    sanitazeOnMutation(SET_CRED_SOURCE);
                }

                if (this.setRealm != null) {
                    sanitazeOnMutation(SET_REALM);
                }

                if (this.parameterSpecs != null) {
                    sanitazeOnMutation(SET_PARAM_SPECS);
                }

                if (this.keyManagerFactory != null) {
                    sanitazeOnMutation(SET_KEY_MGR_FAC);
                }
                break;
        }
    }

    AccessControlContext getCapturedContext() {
        return capturedAccessContext;
    }

    // delegates for equality tests

    // interfaces

    static class ClientCallbackHandler implements CallbackHandler {
        private final AuthenticationConfiguration config;
        private final CallbackHandler userCallbackHandler;
        private List<TrustedAuthority> trustedAuthorities;
        private SSLConnection sslConnection;

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
                    if (principal instanceof AnonymousPrincipal) {
                        final String defaultName = nameCallback.getDefaultName();
                        if (defaultName != null) {
                            nameCallback.setName(defaultName);
                        }
                        // otherwise set nothing; the mech can decide if that's OK or not
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
                } else if (callback instanceof SSLCallback) {
                    if (config.getUserCallbackKinds().contains(CallbackKind.SSL)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    SSLCallback sslCallback = (SSLCallback) callback;
                    this.sslConnection = sslCallback.getSslConnection();
                    continue;
                } else if (callback instanceof ChannelBindingCallback) {
                    if (config.getUserCallbackKinds().contains(CallbackKind.CHANNEL_BINDING)) {
                        userCallbacks.add(callback);
                        continue;
                    }
                    final SSLConnection sslConnection = this.sslConnection;
                    if (sslConnection != null) {
                        sslConnection.handleChannelBindingCallback((ChannelBindingCallback) callback);
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
                } else if (userCallbackHandler != null) {
                    userCallbacks.add(callback);
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
