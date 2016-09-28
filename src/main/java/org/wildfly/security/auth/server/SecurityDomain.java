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
import static org.wildfly.security._private.ElytronMessages.log;

import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;

import org.jboss.threads.JBossThreadFactory;
import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.permission.ElytronPermission;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * A security domain.  Security domains encapsulate a set of security policies.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SecurityDomain {

    static final ElytronPermission CREATE_SECURITY_DOMAIN = ElytronPermission.forName("createSecurityDomain");
    static final ElytronPermission CREATE_AUTH_CONTEXT = ElytronPermission.forName("createServerAuthenticationContext");

    private final Map<String, RealmInfo> realmMap;
    private final String defaultRealmName;
    private final NameRewriter preRealmRewriter;
    private final RealmMapper realmMapper;
    private final NameRewriter postRealmRewriter;
    private final ThreadLocal<SecurityIdentity> currentSecurityIdentity;
    private final RoleMapper roleMapper;
    private final PrincipalDecoder principalDecoder;
    private final SecurityIdentity anonymousIdentity;
    private final PermissionMapper permissionMapper;
    private final Map<String, RoleMapper> categoryRoleMappers;
    private final UnaryOperator<SecurityIdentity> securityIdentityTransformer;
    private final Predicate<SecurityDomain> trustedSecurityDomain;

    SecurityDomain(Builder builder, final LinkedHashMap<String, RealmInfo> realmMap) {
        this.realmMap = realmMap;
        this.defaultRealmName = builder.defaultRealmName;
        this.preRealmRewriter = builder.preRealmRewriter;
        this.realmMapper = builder.realmMapper;
        this.roleMapper = builder.roleMapper;
        this.permissionMapper = builder.permissionMapper;
        this.postRealmRewriter = builder.postRealmRewriter;
        this.principalDecoder = builder.principalDecoder;
        this.securityIdentityTransformer = builder.securityIdentityTransformer;
        this.trustedSecurityDomain = builder.trustedSecurityDomain;
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
        final RealmInfo realmInfo = new RealmInfo();
        anonymousIdentity = Assert.assertNotNull(securityIdentityTransformer.apply(new SecurityIdentity(this, AnonymousPrincipal.getInstance(), realmInfo, AuthorizationIdentity.EMPTY, copiedRoleMappers, SecurityIdentity.NO_PEER_IDENTITIES, IdentityCredentials.NONE, IdentityCredentials.NONE)));
        currentSecurityIdentity = ThreadLocal.withInitial(() -> anonymousIdentity);
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
     * Map the provided name to a {@link RealmIdentity}.
     *
     * @param name the name to map
     * @return the identity for the name
     * @throws RealmUnavailableException if the realm is not able to perform the mapping
     * @throws IllegalArgumentException if the name is not valid
     */
    public RealmIdentity mapName(String name) throws RealmUnavailableException {
        Assert.checkNotNullParam("name", name);
        name = this.preRealmRewriter.rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }
        String realmName = mapRealmName(name, null, null);
        RealmInfo realmInfo = getRealmInfo(realmName);
        SecurityRealm securityRealm = realmInfo.getSecurityRealm();
        assert securityRealm != null;
        name = this.postRealmRewriter.rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }
        name = realmInfo.getNameRewriter().rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }
        return securityRealm.getRealmIdentity(IdentityLocator.fromName(name));
    }

    /**
     * Map the provided principal to a {@link RealmIdentity}.
     *
     * @param principal the principal to map
     * @return the identity for the name
     * @throws IllegalArgumentException if the principal could not be successfully decoded to a name
     * @throws RealmUnavailableException if the realm is not able to perform the mapping
     */
    public RealmIdentity mapPrincipal(Principal principal) throws RealmUnavailableException, IllegalArgumentException {
        Assert.checkNotNullParam("principal", principal);
        final String name = principalDecoder.getName(principal);
        if (name == null) {
            throw ElytronMessages.log.unrecognizedPrincipalType(principal);
        }
        return mapName(name);
    }

    SecurityRealm getRealm(final String realmName) {
        return getRealmInfo(realmName).getSecurityRealm();
    }

    RealmInfo getRealmInfo(final String realmName) {
        RealmInfo realmInfo = this.realmMap.get(realmName);

        if (realmInfo == null) {
            realmInfo = this.realmMap.get(this.defaultRealmName);
        }
        return realmInfo;
    }

    Collection<RealmInfo> getRealmInfos() {
        return realmMap.values();
    }

    /**
     * Determine whether a credential of the given type and algorithm is definitely obtainable, possibly obtainable (for]
     * some identities), or definitely not obtainable.
     *
     * @param credentialType the exact credential type (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type does
     *  not support algorithm names
     * @return the level of support for this credential
     */
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) {
        return getSupportLevel(r -> {
            try {
                return r.getCredentialAcquireSupport(credentialType, algorithmName);
            } catch (RealmUnavailableException e) {
                return null;
            }
        });
    }

    /**
     * Determine whether a credential of the given type and algorithm is definitely obtainable, possibly obtainable (for]
     * some identities), or definitely not obtainable.
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
                return null;
            }
        });
    }

    /**
     * Determine whether a given type of evidence is definitely verifiable, possibly verifiable (for some identities),
     * or definitely not verifiable.
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
     * @return the current security identity for this domain (not {@code null})
     */
    public SecurityIdentity getCurrentSecurityIdentity() {
        final SecurityIdentity identity = currentSecurityIdentity.get();
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

    SecurityIdentity getAndSetCurrentSecurityIdentity(SecurityIdentity newIdentity) {
        try {
            final SecurityIdentity oldIdentity = currentSecurityIdentity.get();
            return oldIdentity == null ? anonymousIdentity : oldIdentity;
        } finally {
            if (newIdentity == anonymousIdentity) {
                currentSecurityIdentity.remove();
            } else {
                currentSecurityIdentity.set(newIdentity);
            }
        }
    }

    void setCurrentSecurityIdentity(SecurityIdentity newIdentity) {
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
        RoleDecoder roleDecoder = realmInfo.getRoleDecoder(); // zeroth role mapping, just grab roles from the identity
        Roles mappedRoles = roleDecoder.decodeRoles(identity);
        RoleMapper realmRoleMapper = realmInfo.getRoleMapper();

        // apply the first level mapping, which is based on the role mapper associated with a realm.
        mappedRoles = realmRoleMapper.mapRoles(mappedRoles);

        // apply the second level mapping, which is based on the role mapper associated with this security domain.
        return this.roleMapper.mapRoles(mappedRoles);
    }

    PermissionVerifier mapPermissions(SecurityIdentity securityIdentity) {
        Assert.checkNotNullParam("securityIdentity", securityIdentity);
        Roles roles = securityIdentity.getRoles();

        return this.permissionMapper.mapPermissions(securityIdentity, roles);
    }

    NameRewriter getPreRealmRewriter() {
        return preRealmRewriter;
    }

    String mapRealmName(final String name, final Principal principal, final Evidence evidence) {
        String realm = realmMapper.getRealmMapping(name, principal, evidence);
        return realm != null ? realm : defaultRealmName;
    }

    String getDefaultRealmName() {
        return defaultRealmName;
    }

    RealmMapper getRealmMapper() {
        return realmMapper;
    }

    NameRewriter getPostRealmRewriter() {
        return postRealmRewriter;
    }

    RoleMapper getRoleMapper() {
        return roleMapper;
    }

    PrincipalDecoder getPrincipalDecoder() {
        return principalDecoder;
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
     * A builder for creating new security domains.
     */
    public static final class Builder {
        private boolean built = false;

        private final HashMap<String, RealmBuilder> realms = new HashMap<>();
        private NameRewriter preRealmRewriter = NameRewriter.IDENTITY_REWRITER;
        private NameRewriter postRealmRewriter = NameRewriter.IDENTITY_REWRITER;
        private String defaultRealmName;
        private RealmMapper realmMapper = RealmMapper.DEFAULT_REALM_MAPPER;
        private RoleMapper roleMapper = RoleMapper.IDENTITY_ROLE_MAPPER;
        private PermissionMapper permissionMapper = PermissionMapper.EMPTY_PERMISSION_MAPPER;
        private PrincipalDecoder principalDecoder = PrincipalDecoder.DEFAULT;
        private Map<String, RoleMapper> categoryRoleMappers = emptyMap();
        private UnaryOperator<SecurityIdentity> securityIdentityTransformer = UnaryOperator.identity();
        private Predicate<SecurityDomain> trustedSecurityDomain = domain -> false;

        Builder() {
        }

        /**
         * Sets a pre-realm name rewriter, which rewrites the authentication name before a realm is selected.
         *
         * @param rewriter the name rewriter (must not be {@code null})
         * @return this builder
         */
        public Builder setPreRealmRewriter(NameRewriter rewriter) {
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
            this.principalDecoder = principalDecoder;
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
         * Construct this security domain.
         *
         * @return the new security domain
         */
        public SecurityDomain build() {
            final SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(CREATE_SECURITY_DOMAIN);
            }

            final String defaultRealmName = this.defaultRealmName;
            Assert.checkNotNullParam("defaultRealmName", defaultRealmName);
            final LinkedHashMap<String, RealmInfo> realmMap = new LinkedHashMap<>(realms.size());
            for (RealmBuilder realmBuilder : realms.values()) {
                realmMap.put(realmBuilder.getName(), new RealmInfo(realmBuilder));
            }
            if (!realmMap.containsKey(defaultRealmName)) {
                throw log.realmMapDoesNotContainDefault(defaultRealmName);
            }

            assertNotBuilt();
            built = true;

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
        private NameRewriter nameRewriter = NameRewriter.IDENTITY_REWRITER;
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
        public NameRewriter getNameRewriter() {
            return nameRewriter;
        }

        /**
         * Set the name rewriter.
         *
         * @param nameRewriter the name rewriter (may not be {@code null})
         */
        public RealmBuilder setNameRewriter(final NameRewriter nameRewriter) {
            Assert.checkNotNullParam("nameRewriter", nameRewriter);
            assertNotBuilt();
            this.nameRewriter = nameRewriter;

            return this;
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
        private static final ThreadFactory threadFactory = doPrivileged((PrivilegedAction<JBossThreadFactory>) ()
                -> new JBossThreadFactory(new ThreadGroup("SecurityDomain ThreadGroup"), Boolean.FALSE, null, "%G - %t", null, null));
        private static final ScheduledThreadPoolExecutor INSTANCE = new ScheduledThreadPoolExecutor(1, threadFactory);

        static {
            INSTANCE.setRemoveOnCancelPolicy(true);
            INSTANCE.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        }
    }

    public static ScheduledExecutorService getScheduledExecutorService() {
        return ScheduledExecutorServiceProvider.INSTANCE;
    }
}
