/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.server;

import static java.security.AccessController.doPrivileged;
import static java.util.Collections.emptyMap;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.auth.server._private.ElytronMessages.log;

import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

import org.wildfly.common.Assert;
import org.wildfly.common.function.ExceptionBiFunction;
import org.wildfly.common.function.ExceptionFunction;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.principal.RealmNestedPrincipal;
import org.wildfly.security.auth.server.event.SecurityEvent;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.permission.ElytronPermission;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * A security domain.  Security domains encapsulate a set of security policies.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SecurityDomain {

    private static final ConcurrentHashMap<ClassLoader, SecurityDomain> CLASS_LOADER_DOMAIN_MAP = new ConcurrentHashMap<>();
    private static final RealmInfo EMPTY_REALM_INFO = new RealmInfo();

    static final ElytronPermission AUTHENTICATE = ElytronPermission.forName("authenticate");
    static final ElytronPermission CREATE_SECURITY_DOMAIN = ElytronPermission.forName("createSecurityDomain");
    static final ElytronPermission REGISTER_SECURITY_DOMAIN = ElytronPermission.forName("registerSecurityDomain");
    static final ElytronPermission GET_SECURITY_DOMAIN = ElytronPermission.forName("getSecurityDomain");
    static final ElytronPermission UNREGISTER_SECURITY_DOMAIN = ElytronPermission.forName("unregisterSecurityDomain");
    static final ElytronPermission CREATE_AUTH_CONTEXT = ElytronPermission.forName("createServerAuthenticationContext");
    static final ElytronPermission GET_IDENTITY = ElytronPermission.forName("getIdentity");
    static final ElytronPermission GET_IDENTITY_FOR_UPDATE = ElytronPermission.forName("getIdentityForUpdate");
    static final ElytronPermission CREATE_AD_HOC_IDENTITY = ElytronPermission.forName("createAdHocIdentity");
    static final ElytronPermission HANDLE_SECURITY_EVENT = ElytronPermission.forName("handleSecurityEvent");

    private final Map<String, RealmInfo> realmMap;
    private final String defaultRealmName;
    private final Function<Principal, Principal> preRealmPrincipalRewriter;
    private final RealmMapper realmMapper;
    private final Function<Principal, Principal> postRealmPrincipalRewriter;
    private final ThreadLocal<Supplier<SecurityIdentity>> currentSecurityIdentity;
    private final RoleMapper roleMapper;
    private final SecurityIdentity anonymousIdentity;
    private final PermissionMapper permissionMapper;
    private final Map<String, RoleMapper> categoryRoleMappers;
    private final UnaryOperator<SecurityIdentity> securityIdentityTransformer;
    private final Predicate<SecurityDomain> trustedSecurityDomain;
    private final Consumer<SecurityEvent> securityEventListener;
    private final Function<Evidence, Principal> evidenceDecoder;
    private final RoleDecoder roleDecoder;

    SecurityDomain(Builder builder, final LinkedHashMap<String, RealmInfo> realmMap) {
        this.realmMap = realmMap;
        this.defaultRealmName = builder.defaultRealmName;
        this.preRealmPrincipalRewriter = builder.principalDecoder.andThen(builder.preRealmRewriter);
        this.realmMapper = builder.realmMapper;
        this.roleMapper = builder.roleMapper;
        this.permissionMapper = builder.permissionMapper;
        this.postRealmPrincipalRewriter = builder.postRealmRewriter;
        this.securityIdentityTransformer = builder.securityIdentityTransformer;
        this.trustedSecurityDomain = builder.trustedSecurityDomain;
        this.securityEventListener = builder.securityEventListener;
        this.evidenceDecoder = builder.evidenceDecoder;
        this.roleDecoder = builder.roleDecoder;
        final Map<String, RoleMapper> originalRoleMappers = builder.categoryRoleMappers;
        final Map<String, RoleMapper> copiedRoleMappers;
        if (originalRoleMappers.isEmpty()) {
            copiedRoleMappers = emptyMap();
        } else if (originalRoleMappers.size() == 1) {
            final Map.Entry<String, RoleMapper> entry = originalRoleMappers.entrySet().iterator().next();
            copiedRoleMappers = Collections.singletonMap(entry.getKey(), entry.getValue());
        } else {
            copiedRoleMappers = new LinkedHashMap<>(originalRoleMappers);
        }
        this.categoryRoleMappers = copiedRoleMappers;
        // todo configurable
        anonymousIdentity = Assert.assertNotNull(securityIdentityTransformer.apply(new SecurityIdentity(this, AnonymousPrincipal.getInstance(), EMPTY_REALM_INFO, AuthorizationIdentity.EMPTY, copiedRoleMappers, IdentityCredentials.NONE, IdentityCredentials.NONE)));
        currentSecurityIdentity = ThreadLocal.withInitial(() -> anonymousIdentity);
    }

    /**
     * Register this {@link SecurityDomain} with the specified {@link ClassLoader}.
     *
     * Registration with enabled security manager requires {@code registerSecurityDomain} {@link ElytronPermission}.
     *
     * @throws IllegalStateException If a {@link SecurityDomain} is already associated with the specified {@link ClassLoader}.
     * @param classLoader the non {@code null} {@link ClassLoader} to associate this {@link SecurityDomain} with.
     */
    public void registerWithClassLoader(ClassLoader classLoader) {
        checkNotNullParam("classLoader", classLoader);
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(REGISTER_SECURITY_DOMAIN);
        }

        final SecurityDomain classLoaderDomain = CLASS_LOADER_DOMAIN_MAP.putIfAbsent(classLoader, this);
        if ((classLoaderDomain != null) && (classLoaderDomain != this)) {
            throw log.classLoaderSecurityDomainExists();
        }
    }

    /**
     * Get the {@link SecurityDomain} associated with the context class loader of the calling Thread or {@code null} if one is
     * not associated.
     *
     * Obtaining security domain with enabled security manager requires {@code getSecurityDomain} {@link ElytronPermission}.
     *
     * @return the {@link SecurityDomain} associated with the context class loader of the calling Thread or {@code null} if one
     *         is not associated.
     */
    public static SecurityDomain getCurrent() {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(GET_SECURITY_DOMAIN);
        }

        final Thread currentThread = Thread.currentThread();
        ClassLoader classLoader;
        if (sm != null) {
            classLoader = doPrivileged((PrivilegedAction<ClassLoader>) currentThread::getContextClassLoader);
        } else {
            classLoader = currentThread.getContextClassLoader();
        }

        return classLoader != null ? CLASS_LOADER_DOMAIN_MAP.get(classLoader) : null;
    }

    /**
     * Get the security domain associated with the given identity.
     *
     * Obtaining security domain with enabled security manager requires {@code getSecurityDomain} {@link ElytronPermission}.
     *
     * @param identity the security identity (must not be {@code null})
     * @return the identity's security domain (not {@code null})
     */
    public static SecurityDomain forIdentity(SecurityIdentity identity) {
        checkNotNullParam("identity", identity);
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(GET_SECURITY_DOMAIN);
        }
        return identity.getSecurityDomain();
    }

    /**
     * Unregister any {@link SecurityDomain} associated with the specified {@link ClassLoader}.
     *
     * Unregistration with enabled security manager requires {@code unregisterSecurityDomain} {@link ElytronPermission}.
     *
     * @param classLoader the non {@code null} {@link ClassLoader} to clear any {@link SecurityDomain} association.
     */
    public static void unregisterClassLoader(ClassLoader classLoader) {
        checkNotNullParam("classLoader", classLoader);
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(UNREGISTER_SECURITY_DOMAIN);
        }

        CLASS_LOADER_DOMAIN_MAP.remove(classLoader);
    }

    /**
     * Create a new security domain builder.
     *
     * @return the builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Create a new authentication context for this security domain which can be used to carry out a single authentication
     * operation.
     *
     * Calling with enabled security manager requires {@code createServerAuthenticationContext} {@link ElytronPermission}.
     *
     * @return the new authentication context
     */
    public ServerAuthenticationContext createNewAuthenticationContext() {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(CREATE_AUTH_CONTEXT);
        }
        return new ServerAuthenticationContext(this, MechanismConfigurationSelector.constantSelector(MechanismConfiguration.EMPTY));
    }

    /**
     * Create a new authentication context for this security domain which can be used to carry out a single authentication
     * operation.
     *
     * Calling with enabled security manager requires {@code createServerAuthenticationContext} {@link ElytronPermission}.
     *
     * @param mechanismConfigurationSelector the selector to use to obtain the mechanism configuration
     * @return the new authentication context
     */
    public ServerAuthenticationContext createNewAuthenticationContext(MechanismConfigurationSelector mechanismConfigurationSelector) {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(CREATE_AUTH_CONTEXT);
        }
        return new ServerAuthenticationContext(this, mechanismConfigurationSelector);
    }

    ServerAuthenticationContext createNewAuthenticationContext(SecurityIdentity capturedIdentity, MechanismConfigurationSelector mechanismConfigurationSelector) {
        assert capturedIdentity.getSecurityDomain() == this;
        return new ServerAuthenticationContext(capturedIdentity, mechanismConfigurationSelector);
    }

    /**
     * Perform an authentication based on {@link Evidence} alone.
     *
     * Note:  It is the caller's responsibility to destroy any evidence passed into this method.
     *
     * @param evidence the {@link Evidence} to use for authentication.
     * @return the authenticated identity.
     * @throws RealmUnavailableException if the requires {@link SecurityRealm} is not available.
     * @throws SecurityException if authentication fails.
     */
    public SecurityIdentity authenticate(Evidence evidence) throws RealmUnavailableException, SecurityException {
        return authenticate((Principal) null, evidence);
    }

    /**
     * Perform an authentication based on {@link Evidence} for the specified identity name.
     *
     * Note:  It is the caller's responsibility to destroy any evidence passed into this method.
     *
     * @param name the name of the identity to authenticate or {@code null} if the identity is to be derived from the evidence.
     * @param evidence the {@link Evidence} to use for authentication.
     * @return the authenticated identity.
     * @throws RealmUnavailableException if the requires {@link SecurityRealm} is not available.
     * @throws SecurityException if authentication fails.
     */
    public SecurityIdentity authenticate(String name, Evidence evidence) throws RealmUnavailableException, SecurityException {
        return authenticate(name != null ? new NamePrincipal(name) : null, evidence);
    }

    /**
     * Perform an authentication based on {@link Evidence} for the specified identity {@link Principal}.
     *
     * Note:  It is the caller's responsibility to destroy any evidence passed into this method.
     *
     * Calling with enabled security manager requires {@code authenticate} {@link ElytronPermission}.
     *
     * @param principal the principal of the identity to authenticate or {@code null} if the identity is to be derived from the evidence.
     * @param evidence the {@link Evidence} to use for authentication.
     * @return the authenticated identity.
     * @throws RealmUnavailableException if the requires {@link SecurityRealm} is not available.
     * @throws SecurityException if authentication fails.
     */
    public SecurityIdentity authenticate(Principal principal, Evidence evidence) throws RealmUnavailableException, SecurityException {
        final SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkPermission(AUTHENTICATE);
        }

        ServerAuthenticationContext serverAuthenticationContext = new ServerAuthenticationContext(this, MechanismConfigurationSelector.constantSelector(MechanismConfiguration.EMPTY));
        if (principal != null) serverAuthenticationContext.setAuthenticationPrincipal(principal);
        if (serverAuthenticationContext.verifyEvidence(evidence)) {
            if (serverAuthenticationContext.authorize()) {
                if (evidence instanceof PasswordGuessEvidence) {
                    PasswordGuessEvidence passwordGuessEvidence = PasswordGuessEvidence.class.cast(evidence);
                    serverAuthenticationContext.addPrivateCredential(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, passwordGuessEvidence.getGuess())));
                } else if (evidence instanceof BearerTokenEvidence) {
                    BearerTokenEvidence tokenEvidence = BearerTokenEvidence.class.cast(evidence);
                    serverAuthenticationContext.addPrivateCredential(new BearerTokenCredential(tokenEvidence.getToken()));
                } else {
                    log.tracef("Evidence [%s] does not map to a supported credential type. Credentials are not available from authorized identity and identity propagation may not work", evidence.getClass().getName());
                }
                serverAuthenticationContext.succeed();
                return serverAuthenticationContext.getAuthorizedIdentity();
            } else {
                serverAuthenticationContext.fail();
                throw log.authenticationFailedAuthorization();
            }
        } else {
            serverAuthenticationContext.fail();
            throw log.authenticationFailedEvidenceVerification();
        }
    }

    /**
     * Look up a {@link RealmIdentity} by name by wrapping the name in a {@link NamePrincipal} and calling {@link #getIdentity(Principal)}.
     * The returned identity must be {@linkplain RealmIdentity#dispose() disposed}.
     *
     * @param name the name to map (must not be {@code null})
     * @return the identity for the name (not {@code null}, may be non-existent)
     * @throws RealmUnavailableException if the realm is not able to perform the mapping
     * @throws IllegalArgumentException if the name is not valid
     * @throws SecurityException if the caller is not authorized to perform the operation
     */
    public RealmIdentity getIdentity(String name) throws RealmUnavailableException {
        Assert.checkNotNullParam("name", name);
        return getIdentity(new NamePrincipal(name));
    }

    /**
     * Look up a {@link RealmIdentity} by principal.
     * The returned identity must be {@linkplain RealmIdentity#dispose() disposed}.
     *
     * Calling with enabled security manager requires {@code getIdentity} {@link ElytronPermission}.
     *
     * @param principal the principal to map (must not be {@code null})
     * @return the identity for the name (not {@code null}, may be non-existent)
     * @throws IllegalArgumentException if the principal could not be successfully decoded to a name
     * @throws RealmUnavailableException if the realm is not able to perform the mapping
     * @throws SecurityException if the caller is not authorized to perform the operation
     */
    public RealmIdentity getIdentity(Principal principal) throws RealmUnavailableException, IllegalArgumentException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(GET_IDENTITY);
        }
        return getIdentityPrivileged(principal, SecurityRealm.class, SecurityRealm::getRealmIdentity, () -> RealmIdentity.NON_EXISTENT, () -> RealmIdentity.ANONYMOUS);
    }

    /**
     * Look up a {@link ModifiableRealmIdentity} by principal.
     * The returned identity must be {@linkplain RealmIdentity#dispose() disposed}.
     *
     * Calling with enabled security manager requires {@code getIdentityForUpdate} {@link ElytronPermission}.
     *
     * @param principal the principal to map (must not be {@code null})
     * @return the identity for the name (not {@code null}, may be non-existent)
     * @throws IllegalArgumentException if the principal could not be successfully decoded to a name
     * @throws RealmUnavailableException if the realm is not able to perform the mapping
     * @throws SecurityException if the caller is not authorized to perform the operation
     */
    public ModifiableRealmIdentity getIdentityForUpdate(Principal principal) throws RealmUnavailableException, IllegalArgumentException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(GET_IDENTITY_FOR_UPDATE);
        }
        return getIdentityPrivileged(principal, ModifiableSecurityRealm.class, ModifiableSecurityRealm::getRealmIdentityForUpdate, () -> ModifiableRealmIdentity.NON_EXISTENT, () -> ModifiableRealmIdentity.NON_EXISTENT);
    }

    /**
     * Get a function which can be used to look up principals without a security manager permission check.
     * All returned identities must be {@linkplain RealmIdentity#dispose() disposed}.
     *
     * Calling with enabled security manager requires {@code getIdentity} {@link ElytronPermission}.
     *
     * @return the lookup function (not {@code null})
     * @throws SecurityException if the caller is not authorized to perform the operation
     */
    public ExceptionFunction<Principal, RealmIdentity, RealmUnavailableException> getIdentityLookupFunction() {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(GET_IDENTITY);
        }
        return p -> getIdentityPrivileged(p, SecurityRealm.class, SecurityRealm::getRealmIdentity, () -> RealmIdentity.NON_EXISTENT, () -> RealmIdentity.ANONYMOUS);
    }

    /**
     * Get a function which can be used to look up principals for update without a security manager permission check.
     * All returned identities must be {@linkplain RealmIdentity#dispose() disposed}.
     * Calling with enabled security manager requires {@code getIdentityForUpdate} {@link ElytronPermission}.
     *
     * @return the lookup function (not {@code null})
     * @throws SecurityException if the caller is not authorized to perform the operation
     */
    public ExceptionFunction<Principal, ModifiableRealmIdentity, RealmUnavailableException> getIdentityLookupForUpdateFunction() {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(GET_IDENTITY_FOR_UPDATE);
        }
        return p -> getIdentityPrivileged(p, ModifiableSecurityRealm.class, ModifiableSecurityRealm::getRealmIdentityForUpdate, () -> ModifiableRealmIdentity.NON_EXISTENT, () -> ModifiableRealmIdentity.NON_EXISTENT);
    }

    <I, R extends SecurityRealm> I getIdentityPrivileged(Principal principal, Class<R> realmType, ExceptionBiFunction<R, Principal, I, RealmUnavailableException> fn, Supplier<I> nonExistent, Supplier<I> anonymous) throws RealmUnavailableException {
        Assert.checkNotNullParam("principal", principal);
        if (principal instanceof AnonymousPrincipal) {
            return anonymous.get();
        }
        if (principal instanceof RealmNestedPrincipal) {
            final RealmNestedPrincipal realmNestedPrincipal = (RealmNestedPrincipal) principal;
            final SecurityRealm securityRealm = getRealmInfo(realmNestedPrincipal.getRealmName()).getSecurityRealm();
            if (realmType.isInstance(securityRealm)) {
                return fn.apply(realmType.cast(securityRealm), realmNestedPrincipal.getNestedPrincipal());
            } else {
                return nonExistent.get();
            }
        }
        Principal preRealmPrincipal = preRealmPrincipalRewriter.apply(principal);
        if (preRealmPrincipal == null) {
            throw log.invalidName();
        }

        String realmName = mapRealmName(preRealmPrincipal, null);
        RealmInfo realmInfo = getRealmInfo(realmName);
        SecurityRealm securityRealm = realmInfo.getSecurityRealm();
        assert securityRealm != null;

        Principal postRealmPrincipal = postRealmPrincipalRewriter.apply(preRealmPrincipal);
        if (postRealmPrincipal == null) {
            throw log.invalidName();
        }

        Principal realmRewrittenPrincipal = realmInfo.getPrincipalRewriter().apply(postRealmPrincipal);
        if (realmRewrittenPrincipal == null) {
            throw log.invalidName();
        }

        log.tracef("Principal mapping: [%s], pre-realm rewritten: [%s], realm name: [%s], post realm rewritten: [%s], realm rewritten: [%s]",
                principal, preRealmPrincipal, realmName, postRealmPrincipal, realmRewrittenPrincipal);

        if (realmType.isInstance(securityRealm)) {
            return fn.apply(realmType.cast(securityRealm), realmRewrittenPrincipal);
        } else {
            return nonExistent.get();
        }
    }

    SecurityRealm getRealm(final String realmName) {
        return getRealmInfo(realmName).getSecurityRealm();
    }

    RealmInfo getRealmInfo(final String realmName) {
        RealmInfo realmInfo = this.realmMap.get(realmName);

        if (realmInfo == null) {
            realmInfo = this.realmMap.get(this.defaultRealmName);
        }
        if (realmInfo == null) {
            log.tracef("Unable to obtain RealmInfo [%s] and no default set - using empty", realmName);
            realmInfo = EMPTY_REALM_INFO;
        }
        return realmInfo;
    }

    Collection<RealmInfo> getRealmInfos() {
        return realmMap.values();
    }

    /**
     * Determine whether a credential of the given type and algorithm is definitely obtainable, possibly obtainable (for
     * some identities), or definitely not obtainable.
     *
     * Credential is {@link SupportLevel#SUPPORTED}, if it is supported by all realms of the domain.
     * Credential is {@link SupportLevel#POSSIBLY_SUPPORTED} if it is supported or possibly supported by at least one realm of the domain.
     * Otherwise it is {@link SupportLevel#UNSUPPORTED}.
     *
     * @param credentialType the exact credential type (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type does
     *  not support algorithm names
     * @param parameterSpec the algorithm parameters to match, or {@code null} if any parameters are acceptable or the credential type
     *  does not support algorithm parameters
     * @return the level of support for this credential
     */
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
        return getSupportLevel(r -> {
            try {
                return r.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
            } catch (RealmUnavailableException e) {
                log.trace("Failed to obtain credential acquire support from realm", e);
                return null;
            }
        });
    }

    /**
     * Determine whether a credential of the given type and algorithm is definitely obtainable, possibly obtainable (for
     * some identities), or definitely not obtainable.
     *
     * Credential is {@link SupportLevel#SUPPORTED}, if it is supported by all realms of the domain.
     * Credential is {@link SupportLevel#POSSIBLY_SUPPORTED} if it is supported or possibly supported by at least one realm of the domain.
     * Otherwise it is {@link SupportLevel#UNSUPPORTED}.
     *
     * @param credentialType the exact credential type (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type does
     *  not support algorithm names
     * @return the level of support for this credential
     */
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) {
        return getCredentialAcquireSupport(credentialType, algorithmName, null);
    }

    /**
     * Determine whether a credential of the given type and algorithm is definitely obtainable, possibly obtainable (for
     * some identities), or definitely not obtainable.
     *
     * Credential is {@link SupportLevel#SUPPORTED}, if it is supported by all realms of the domain.
     * Credential is {@link SupportLevel#POSSIBLY_SUPPORTED} if it is supported or possibly supported by at least one realm of the domain.
     * Otherwise it is {@link SupportLevel#UNSUPPORTED}.
     *
     * @param credentialType the exact credential type (must not be {@code null})
     * @return the level of support for this credential
     */
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType) {
        return getCredentialAcquireSupport(credentialType, null);
    }

    /**
     * Determine whether a given type of evidence is definitely verifiable, possibly verifiable (for some identities),
     * or definitely not verifiable.
     *
     * Evidence is {@link SupportLevel#SUPPORTED}, if it is supported by all realms of the domain.
     * Evidence is {@link SupportLevel#POSSIBLY_SUPPORTED} if it is supported or possibly supported by at least one realm of the domain.
     * Otherwise it is {@link SupportLevel#UNSUPPORTED}.
     *
     * @param evidenceType the type of evidence to be verified (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the evidence type does
     *  not support algorithm names
     * @return the level of support for this evidence type
     */
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
        return getSupportLevel(r -> {
            try {
                return r.getEvidenceVerifySupport(evidenceType, algorithmName);
            } catch (RealmUnavailableException e) {
                log.trace("Failed to obtain evidence verify support from realm", e);
                return null;
            }
        });
    }

    /**
     * Determine whether a given type of evidence is definitely verifiable, possibly verifiable (for some identities),
     * or definitely not verifiable.
     *
     * Evidence is {@link SupportLevel#SUPPORTED}, if it is supported by all realms of the domain.
     * Evidence is {@link SupportLevel#POSSIBLY_SUPPORTED} if it is supported or possibly supported by at least one realm of the domain.
     * Otherwise it is {@link SupportLevel#UNSUPPORTED}.
     *
     * @param evidenceType the type of evidence to be verified (must not be {@code null})
     * @return the level of support for this evidence type
     */
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType) {
        return getEvidenceVerifySupport(evidenceType, null);
    }

    private SupportLevel getSupportLevel(final Function<SecurityRealm, SupportLevel> getSupportLevel) {
        SupportLevel min, max;
        min = max = null;
        Iterator<RealmInfo> iterator = realmMap.values().iterator();

        while (iterator.hasNext()) {
            RealmInfo realmInfo = iterator.next();
            SecurityRealm realm = realmInfo.getSecurityRealm();
            final SupportLevel support = getSupportLevel.apply(realm);

            if (support != null) {
                if (min == null || max == null) {
                    min = max = support;
                } else {
                    if (support.compareTo(min) < 0) { min = support; }
                    if (support.compareTo(max) > 0) { max = support; }
                }
            }
        }

        if (min == null || max == null) {
            return SupportLevel.UNSUPPORTED;
        } else {
            return minMax(min, max);
        }
    }

    private SupportLevel minMax(SupportLevel min, SupportLevel max) {
        if (min == max) return min;
        if (max == SupportLevel.UNSUPPORTED) {
            return SupportLevel.UNSUPPORTED;
        } else if (min == SupportLevel.SUPPORTED) {
            return SupportLevel.SUPPORTED;
        } else {
            return SupportLevel.POSSIBLY_SUPPORTED;
        }
    }

    /**
     * Get the current security identity for this domain.
     *
     * Code can be executed with given identity using {@code SecurityIdentity.runAs*} methods.
     *
     * @return the current security identity for this domain (not {@code null})
     */
    public SecurityIdentity getCurrentSecurityIdentity() {
        final SecurityIdentity identity = currentSecurityIdentity.get().get();
        return identity == null ? anonymousIdentity : identity;
    }

    /**
     * Get the anonymous security identity for this realm.
     *
     * @return the anonymous security identity for this realm (not {@code null})
     */
    public SecurityIdentity getAnonymousSecurityIdentity() {
        return anonymousIdentity;
    }

    /**
     * Create an empty ad-hoc identity.  The identity will have no authorization information and no credentials associated
     * with it.
     *
     * @param name the identity name (must not be {@code null})
     * @return the ad-hoc identity
     */
    public SecurityIdentity createAdHocIdentity(String name) {
        checkNotNullParam("name", name);
        return createAdHocIdentity(new NamePrincipal(name));
    }

    /**
     * Create an empty ad-hoc identity.  The identity will have no authorization information and no credentials associated
     * with it.
     *
     * Calling with enabled security manager requires {@code createAdHocIdentity} {@link ElytronPermission}.
     *
     * @param principal the identity principal (must not be {@code null})
     * @return the ad-hoc identity
     */
    public SecurityIdentity createAdHocIdentity(Principal principal) {
        checkNotNullParam("principal", principal);
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(CREATE_AD_HOC_IDENTITY);
        }
        return new SecurityIdentity(this, principal, EMPTY_REALM_INFO, AuthorizationIdentity.EMPTY, emptyMap(), IdentityCredentials.NONE, IdentityCredentials.NONE);
    }

    Supplier<SecurityIdentity> getAndSetCurrentSecurityIdentity(Supplier<SecurityIdentity> newIdentity) {
        try {
            final Supplier<SecurityIdentity> oldIdentity = currentSecurityIdentity.get();
            return oldIdentity == null ? anonymousIdentity : oldIdentity;
        } finally {
            if (newIdentity == anonymousIdentity) {
                currentSecurityIdentity.remove();
            } else {
                currentSecurityIdentity.set(newIdentity);
            }
        }
    }

    void setCurrentSecurityIdentity(Supplier<SecurityIdentity> newIdentity) {
        if (newIdentity == anonymousIdentity) {
            currentSecurityIdentity.remove();
        } else {
            currentSecurityIdentity.set(newIdentity);
        }
    }

    Roles mapRoles(SecurityIdentity securityIdentity) {
        Assert.checkNotNullParam("securityIdentity", securityIdentity);

        AuthorizationIdentity identity = securityIdentity.getAuthorizationIdentity();
        RealmInfo realmInfo = securityIdentity.getRealmInfo();

        // zeroth role mapping, just grab roles from the identity
        Roles decodedRoles = realmInfo.getRoleDecoder().decodeRoles(identity);

        // determine roles based on any runtime attributes associated with the identity
        Roles domainDecodedRoles = securityIdentity.getSecurityDomain().getRoleDecoder().decodeRoles(identity);
        Roles combinedRoles = decodedRoles.or(domainDecodedRoles);

        // apply the first level mapping, which is based on the role mapper associated with a realm.
        Roles realmMappedRoles = realmInfo.getRoleMapper().mapRoles(combinedRoles);

        // apply the second level mapping, which is based on the role mapper associated with this security domain.
        Roles domainMappedRoles = roleMapper.mapRoles(realmMappedRoles);

        if (log.isTraceEnabled()) {
            log.tracef("Role mapping: principal [%s] -> decoded roles [%s] -> domain decoded roles [%s] -> realm mapped roles [%s] -> domain mapped roles [%s]",
                    securityIdentity.getPrincipal(), String.join(", ", decodedRoles), String.join(", ", domainDecodedRoles), String.join(", ", realmMappedRoles), String.join(", ", domainMappedRoles));
        }

        return domainMappedRoles;
    }

    PermissionVerifier mapPermissions(final SecurityIdentity securityIdentity) {
        Assert.checkNotNullParam("securityIdentity", securityIdentity);
        final Roles roles = securityIdentity.getRoles();
        PermissionVerifier verifier = permissionMapper.mapPermissions(securityIdentity, roles);

        if (log.isTraceEnabled()) {
            return (permission) -> {
                boolean decision = verifier.implies(permission);
                log.tracef("Permission mapping: identity [%s] with roles [%s] implies %s = %b",
                        securityIdentity.getPrincipal(), String.join(", ", roles), permission, decision);
                return decision;
            };
        } else {
            return verifier;
        }
    }

    Function<Principal, Principal> getPreRealmRewriter() {
        return preRealmPrincipalRewriter;
    }

    String mapRealmName(final Principal principal, final Evidence evidence) {
        String realm = realmMapper.getRealmMapping(principal, evidence);
        return realm != null ? realm : defaultRealmName;
    }

    String getDefaultRealmName() {
        return defaultRealmName;
    }

    RealmMapper getRealmMapper() {
        return realmMapper;
    }

    Function<Principal, Principal> getPostRealmRewriter() {
        return postRealmPrincipalRewriter;
    }

    RoleMapper getRoleMapper() {
        return roleMapper;
    }

    Map<String, RoleMapper> getCategoryRoleMappers() {
        return categoryRoleMappers;
    }

    SecurityIdentity transform(final SecurityIdentity securityIdentity) {
        Assert.checkNotNullParam("securityIdentity", securityIdentity);
        return Assert.assertNotNull(securityIdentityTransformer.apply(securityIdentity));
    }

    boolean trustsDomain(final SecurityDomain domain) {
        Assert.checkNotNullParam("domain", domain);
        return this == domain || trustedSecurityDomain.test(domain);
    }

    /**
     * Handle a {@link SecurityEvent}.
     *
     * Calling with enabled security manager requires {@code handleSecurityEvent} {@link ElytronPermission}.
     *
     * @param securityEvent {@link SecurityEvent} to be handled
     * @see Builder#setSecurityEventListener(Consumer)
     */
    public void handleSecurityEvent(final SecurityEvent securityEvent) {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(HANDLE_SECURITY_EVENT);
        }
        if (!securityEvent.getSecurityIdentity().getSecurityDomain().equals(this)) {
            log.securityEventIdentityWrongDomain();
        }
        this.securityEventListener.accept(securityEvent);
    }

    static void safeHandleSecurityEvent(final SecurityDomain domain, final SecurityEvent event) {
        checkNotNullParam("domain", domain);
        checkNotNullParam("event", event);
        try {
            domain.handleSecurityEvent(event);
        } catch (Exception e) {
            log.eventHandlerFailed(e);
        }
    }

    Function<Evidence, Principal> getEvidenceDecoder() {
        return evidenceDecoder;
    }

    RoleDecoder getRoleDecoder() {
        return roleDecoder;
    }

    /**
     * A builder for creating new security domains.
     */
    public static final class Builder {
        private boolean built = false;

        private final HashMap<String, RealmBuilder> realms = new HashMap<>();
        private Function<Principal, Principal> preRealmRewriter = Function.identity();
        private Function<Principal, Principal> principalDecoder = Function.identity();
        private Function<Principal, Principal> postRealmRewriter = Function.identity();
        private String defaultRealmName;
        private RealmMapper realmMapper = RealmMapper.DEFAULT_REALM_MAPPER;
        private RoleMapper roleMapper = RoleMapper.IDENTITY_ROLE_MAPPER;
        private PermissionMapper permissionMapper = PermissionMapper.EMPTY_PERMISSION_MAPPER;
        private Map<String, RoleMapper> categoryRoleMappers = emptyMap();
        private UnaryOperator<SecurityIdentity> securityIdentityTransformer = UnaryOperator.identity();
        private Predicate<SecurityDomain> trustedSecurityDomain = domain -> false;
        private Consumer<SecurityEvent> securityEventListener = e -> {};
        private Function<Evidence, Principal> evidenceDecoder = evidence -> evidence.getDefaultPrincipal();
        private RoleDecoder roleDecoder = RoleDecoder.EMPTY;

        Builder() {
        }

        /**
         * Sets a pre-realm name rewriter, which rewrites the authentication name before a realm is selected.
         *
         * @param rewriter the name rewriter (must not be {@code null})
         * @return this builder
         */
        public Builder setPreRealmRewriter(NameRewriter rewriter) {
            return setPreRealmRewriter(rewriter.asPrincipalRewriter());
        }

        /**
         * Sets a pre-realm name rewriter, which rewrites the authentication name before a realm is selected.
         *
         * @param rewriter the name rewriter (must not be {@code null})
         * @return this builder
         */
        public Builder setPreRealmRewriter(final Function<Principal, Principal> rewriter) {
            Assert.checkNotNullParam("rewriter", rewriter);
            assertNotBuilt();
            this.preRealmRewriter = rewriter;
            return this;
        }

        /**
         * Sets a post-realm name rewriter, which rewrites the authentication name after a realm is selected.
         *
         * @param rewriter the name rewriter (must not be {@code null})
         * @return this builder
         */
        public Builder setPostRealmRewriter(NameRewriter rewriter) {
            return setPostRealmRewriter(rewriter.asPrincipalRewriter());
        }

        /**
         * Sets a post-realm name rewriter, which rewrites the authentication name after a realm is selected.
         *
         * @param rewriter the name rewriter (must not be {@code null})
         * @return this builder
         */
        public Builder setPostRealmRewriter(Function<Principal, Principal> rewriter) {
            Assert.checkNotNullParam("rewriter", rewriter);
            assertNotBuilt();
            this.postRealmRewriter = rewriter;

            return this;
        }

        /**
         * Set the realm mapper for this security domain, which selects a realm based on the authentication name.
         *
         * @param realmMapper the realm mapper (must not be {@code null})
         * @return this builder
         */
        public Builder setRealmMapper(RealmMapper realmMapper) {
            Assert.checkNotNullParam("realmMapper", realmMapper);
            assertNotBuilt();
            this.realmMapper = realmMapper;

            return this;
        }

        /**
         * Set the role mapper for this security domain, which will be used to perform the last mapping before
         * returning the roles associated with an identity obtained from this security domain.
         *
         * @param roleMapper the role mapper (must not be {@code null})
         * @return this builder
         */
        public Builder setRoleMapper(RoleMapper roleMapper) {
            Assert.checkNotNullParam("roleMapper", roleMapper);
            assertNotBuilt();
            this.roleMapper = roleMapper;
            return this;
        }

        /**
         * Set the permission mapper for this security domain, which will be used to obtain and map permissions based on the
         * identities from this security domain.
         *
         * @param permissionMapper the permission mapper (must not be {@code null})
         * @return this builder
         */
        public Builder setPermissionMapper(PermissionMapper permissionMapper) {
            Assert.checkNotNullParam("permissionMapper", permissionMapper);
            assertNotBuilt();
            this.permissionMapper = permissionMapper;
            return this;
        }

        /**
         * Set the principal decoder for this security domain, which will be used to convert {@link Principal} objects
         * into names for handling in the realm.
         *
         * @param principalDecoder the principal decoder (must not be {@code null})
         * @return this builder
         */
        public Builder setPrincipalDecoder(PrincipalDecoder principalDecoder) {
            Assert.checkNotNullParam("principalDecoder", principalDecoder);
            assertNotBuilt();
            this.principalDecoder = principalDecoder.asPrincipalRewriter();
            return this;
        }

        /**
         * Add a realm to this security domain.
         *
         * @param name the realm's name in this configuration
         * @param realm the realm
         * @return the new realm builder
         */
        public RealmBuilder addRealm(String name, SecurityRealm realm) {
            Assert.checkNotNullParam("name", name);
            Assert.checkNotNullParam("realm", realm);
            assertNotBuilt();
            final RealmBuilder realmBuilder = new RealmBuilder(this, name, realm);
            return realmBuilder;
        }

        Builder addRealm(RealmBuilder realmBuilder) {
            realms.put(realmBuilder.getName(), realmBuilder);

            return this;
        }

        /**
         * Get the default realm name.
         *
         * @return the default realm name
         */
        public String getDefaultRealmName() {
            return defaultRealmName;
        }

        /**
         * Set the default realm name.
         *
         * @param defaultRealmName the default realm name (must not be {@code null})
         */
        public Builder setDefaultRealmName(final String defaultRealmName) {
            Assert.checkNotNullParam("defaultRealmName", defaultRealmName);
            assertNotBuilt();
            this.defaultRealmName = defaultRealmName;

            return this;
        }

        /**
         * Get the category role mapper map.
         *
         * @return the category role mapper map
         */
        public Map<String, RoleMapper> getCategoryRoleMappers() {
            return categoryRoleMappers;
        }

        /**
         * Set the category role mapper map.
         *
         * @param categoryRoleMappers the category role mapper map (must not be {@code null})
         */
        public void setCategoryRoleMappers(final Map<String, RoleMapper> categoryRoleMappers) {
            Assert.checkNotNullParam("categoryRoleMappers", categoryRoleMappers);
            this.categoryRoleMappers = categoryRoleMappers;
        }

        /**
         * Set the security identity transformer to use.  The transformer must not return {@code null}, or authentication
         * will fail.
         *
         * @param securityIdentityTransformer the security identity transformer to use (must not be {@code null})
         * @return this builder
         */
        public Builder setSecurityIdentityTransformer(UnaryOperator<SecurityIdentity> securityIdentityTransformer) {
            Assert.checkNotNullParam("securityIdentityTransformer", securityIdentityTransformer);
            this.securityIdentityTransformer = securityIdentityTransformer;
            return this;
        }

        /**
         * Set the predicate that should be used to determine if a given domain is trusted by this domain.
         *
         * @param trustedSecurityDomain the predicate that should be used to determine if a given domain is
         *                              trusted by this domain (must not be {@code null})
         */
        public Builder setTrustedSecurityDomainPredicate(final Predicate<SecurityDomain> trustedSecurityDomain) {
            Assert.checkNotNullParam("trustedSecurityDomain", trustedSecurityDomain);
            this.trustedSecurityDomain = trustedSecurityDomain;
            return this;
        }

        /**
         * Set the security event listener that will consume all {@link SecurityEvent} instances emitted but the domain.
         *
         * @param securityEventListener the security event listener that will consume all {@link SecurityEvent} instances emitted but the domain.
         * @return this builder
         */
        public Builder setSecurityEventListener(final Consumer<SecurityEvent> securityEventListener) {
            this.securityEventListener = Assert.checkNotNullParam("securityEventListener", securityEventListener);
            return this;
        }

        /**
         * Set the evidence decoder for this security domain which will be used to extract the principal from the given
         * {@link Evidence}.
         *
         * @param evidenceDecoder the evidence decoder (must not be {@code null})
         * @return this builder
         * @since 1.10.0
         */
        public Builder setEvidenceDecoder(EvidenceDecoder evidenceDecoder) {
            Assert.checkNotNullParam("evidenceDecoder", evidenceDecoder);
            assertNotBuilt();
            this.evidenceDecoder = evidenceDecoder;
            return this;
        }

        /**
         * Set the role decoder for this security domain.
         *
         * @param roleDecoder the role decoder (must not be {@code null})
         * @return this builder
         * @since 1.11.0
         */
        public Builder setRoleDecoder(RoleDecoder roleDecoder) {
            Assert.checkNotNullParam("roleDecoder", roleDecoder);
            assertNotBuilt();
            this.roleDecoder = roleDecoder;
            return this;
        }

        /**
         * Construct this security domain.
         *
         * Construction requires {@code createSecurityDomain} {@link ElytronPermission}.
         *
         * @return the new security domain
         */
        public SecurityDomain build() {
            final SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(CREATE_SECURITY_DOMAIN);
            }

            final LinkedHashMap<String, RealmInfo> realmMap = new LinkedHashMap<>(realms.size());

            for (RealmBuilder realmBuilder : realms.values()) {
                realmMap.put(realmBuilder.getName(), new RealmInfo(realmBuilder));
            }
            if (defaultRealmName != null && !realmMap.containsKey(defaultRealmName)) {
                throw log.realmMapDoesNotContainDefault(defaultRealmName);
            }

            assertNotBuilt();
            built = true;

            if(log.isTraceEnabled()) {
                log.tracef("Building security domain with defaultRealmName %s.", defaultRealmName);
                if(realmMap.size() > 1) {
                    log.tracef("The following additional realms were added: %s.", realmMap.keySet().toString());
                }
            }

            return new SecurityDomain(this, realmMap);
        }

        void assertNotBuilt() {
            if (built) {
                throw log.builderAlreadyBuilt();
            }
        }
    }

    /**
     * A builder for a realm within a security domain.
     */
    public static class RealmBuilder {

        private final Builder parent;
        private final String name;
        private final SecurityRealm realm;
        private RoleMapper roleMapper = RoleMapper.IDENTITY_ROLE_MAPPER;
        private Function<Principal, Principal> principalRewriter = Function.identity();
        private RoleDecoder roleDecoder = RoleDecoder.DEFAULT;
        private boolean built = false;

        RealmBuilder(final Builder parent, final String name, final SecurityRealm realm) {
            this.parent = parent;
            this.name = name;
            this.realm = realm;
        }

        /**
         * Get the realm name.
         *
         * @return the realm name (not {@code null})
         */
        public String getName() {
            return name;
        }

        /**
         * Get the security realm.
         *
         * @return the security realm (not {@code null})
         */
        public SecurityRealm getRealm() {
            return realm;
        }

        /**
         * Get the role mapper.
         *
         * @return the role mapper (not {@code null})
         */
        public RoleMapper getRoleMapper() {
            return roleMapper;
        }

        /**
         * Set the role mapper.
         *
         * @param roleMapper the role mapper (may not be {@code null})
         */
        public RealmBuilder setRoleMapper(final RoleMapper roleMapper) {
            assertNotBuilt();
            Assert.checkNotNullParam("roleMapper", roleMapper);
            this.roleMapper = roleMapper;

            return this;
        }

        /**
         * Get the name rewriter.
         *
         * @return the name rewriter (not {@code null})
         */
        public Function<Principal, Principal> getPrincipalRewriter() {
            return principalRewriter;
        }

        /**
         * Set the name rewriter.
         *
         * @param principalRewriter the name rewriter (may not be {@code null})
         */
        public RealmBuilder setPrincipalRewriter(final Function<Principal, Principal> principalRewriter) {
            Assert.checkNotNullParam("principalRewriter", principalRewriter);
            assertNotBuilt();
            this.principalRewriter = principalRewriter;

            return this;
        }

        @Deprecated
        public RealmBuilder setNameRewriter(final NameRewriter nameRewriter) {
            return setPrincipalRewriter(nameRewriter.asPrincipalRewriter());
        }

        /**
         * Get the role decoder.
         *
         * @return the role decoder (not {@code null})
         */
        public RoleDecoder getRoleDecoder() {
            return roleDecoder;
        }

        /**
         * Set the role decoder.
         *
         * @param roleDecoder the role decoder (may not be {@code null})
         */
        public RealmBuilder setRoleDecoder(final RoleDecoder roleDecoder) {
            Assert.checkNotNullParam("roleDecoder", roleDecoder);
            assertNotBuilt();
            this.roleDecoder = roleDecoder;

            return this;
        }

        /**
         * Constructs this realm info and adds it into the domain.
         *
         * @return the security domain builder
         */
        public Builder build() {
            assertNotBuilt();
            return parent.addRealm(this);
        }

        private void assertNotBuilt() {
            parent.assertNotBuilt();
            if (built) {
                throw log.builderAlreadyBuilt();
            }
        }
    }

    private static class ScheduledExecutorServiceProvider {

        private static final ScheduledThreadPoolExecutor INSTANCE = new ScheduledThreadPoolExecutor(1);

        static {
            INSTANCE.setRemoveOnCancelPolicy(true);
            INSTANCE.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        }
    }

    /**
     * Gets {@link ScheduledExecutorService} for authentication related scheduled task (like authentication timeout).
     *
     * @return the executor service
     */
    public static ScheduledExecutorService getScheduledExecutorService() {
        return ScheduledExecutorServiceProvider.INSTANCE;
    }
}
