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

import static org.wildfly.security._private.ElytronMessages.log;

import java.security.Security;
import java.security.Provider;
import java.security.PermissionCollection;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import javax.net.ssl.SSLServerSocketFactory;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.permission.ElytronPermission;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.util._private.UnmodifiableArrayList;

/**
 * A security domain.  Security domains encapsulate a set of security policies.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SecurityDomain {

    static final ElytronPermission CREATE_SECURITY_DOMAIN = new ElytronPermission("createSecurityDomain");
    private final Map<String, RealmInfo> realmMap;
    private final String defaultRealmName;
    private final NameRewriter preRealmRewriter;
    private final RealmMapper realmMapper;
    private final NameRewriter postRealmRewriter;
    private final boolean anonymousAllowed;
    private final ThreadLocal<SecurityIdentity> currentSecurityIdentity;
    private final RoleMapper roleMapper;
    private final PrincipalDecoder principalDecoder;
    private final SecurityIdentity anonymousIdentity;
    private final PermissionMapper permissionMapper;
    private final Supplier<Provider[]> providers;

    SecurityDomain(Builder builder, final HashMap<String, RealmInfo> realmMap) {
        this.realmMap = realmMap;
        this.defaultRealmName = builder.defaultRealmName;
        this.preRealmRewriter = builder.preRealmRewriter;
        this.realmMapper = builder.realmMapper;
        this.roleMapper = builder.roleMapper;
        this.permissionMapper = builder.permissionMapper;
        this.postRealmRewriter = builder.postRealmRewriter;
        this.principalDecoder = builder.principalDecoder;
        this.providers = builder.providers;
        // todo configurable
        anonymousAllowed = false;
        final RealmInfo realmInfo = new RealmInfo(SecurityRealm.EMPTY_REALM, "default", RoleMapper.IDENTITY_ROLE_MAPPER, NameRewriter.IDENTITY_REWRITER, RoleDecoder.DEFAULT);
        anonymousIdentity = new SecurityIdentity(this, AnonymousPrincipal.getInstance(), realmInfo, AuthorizationIdentity.EMPTY);
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
        return new ServerAuthenticationContext(this);
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
        String realmName = realmMapper.getRealmMapping(name);
        if (realmName == null) {
            realmName = defaultRealmName;
        }
        SecurityRealm securityRealm = getRealm(realmName);
        assert securityRealm != null;
        name = this.postRealmRewriter.rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }
        return securityRealm.createRealmIdentity(name);
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

    /**
     * Get an SSL server socket factory that authenticates against this security domain.
     *
     * @return the server socket factory
     */
    public SSLServerSocketFactory getSslServerSocketFactory() {
        throw new UnsupportedOperationException();
    }

    /**
     * Get the list of SASL server mechanism names that are provided by the given factory and allowed by this
     * configuration.
     *
     * @param saslServerFactory the SASL server factory
     * @return the list of mechanism names
     */
    public List<String> getSaslServerMechanismNames(SaslServerFactory saslServerFactory) {
        final String[] names = saslServerFactory.getMechanismNames(Collections.singletonMap(WildFlySasl.MECHANISM_QUERY_ALL, "true"));
        // todo: filter down based on SASL selection criteria
        if (names == null || names.length == 0) {
            return Collections.emptyList();
        } else if (names.length == 1) {
            return Collections.singletonList(names[0]);
        } else {
            return new UnmodifiableArrayList<>(names);
        }
    }

    /**
     * Determine whether anonymous authorization is allowed.  Note that this applies only to login authentication
     * protocols and not transport layer security (TLS).
     *
     * @return {@code true} if anonymous logins are allowed, {@code false} if anonymous logins are disallowed
     */
    public boolean isAnonymousAllowed() {
        return anonymousAllowed;
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

    /**
     * Get the {@link Provider} instances associated with this security domain.
     *
     * @return the {@link Provider} instances associated with this security domain.
     */
    Provider[] getProviders() {
        return providers.get();
    }

    CredentialSupport getCredentialSupport(final Class<?> credentialType) {
        SupportLevel obtainMin, obtainMax, verifyMin, verifyMax;
        obtainMin = obtainMax = verifyMin = verifyMax = null;
        Iterator<RealmInfo> iterator = realmMap.values().iterator();
        if (iterator.hasNext()) {

            while (iterator.hasNext()) {
                RealmInfo realmInfo = iterator.next();
                SecurityRealm realm = realmInfo.getSecurityRealm();
                try {
                    final CredentialSupport support = realm.getCredentialSupport(credentialType);

                    final SupportLevel obtainable = support.obtainableSupportLevel();
                    final SupportLevel verification = support.verificationSupportLevel();

                    if (obtainMin == null || obtainMax == null || verifyMin == null || verifyMax == null) {
                        obtainMin = obtainMax = obtainable;
                        verifyMin = verifyMax = verification;
                    } else {
                        if (obtainable.compareTo(obtainMin) < 0) { obtainMin = obtainable; }
                        if (obtainable.compareTo(obtainMax) > 0) { obtainMax = obtainable; }

                        if (verification.compareTo(verifyMin) < 0) { verifyMin = verification; }
                        if (verification.compareTo(verifyMax) > 0) { verifyMax = verification; }
                    }
                } catch (RealmUnavailableException e) {
                }
            }

            if (obtainMin == null || obtainMax == null || verifyMin == null || verifyMax == null) {
                return CredentialSupport.UNSUPPORTED;
            } else {
                return CredentialSupport.getCredentialSupport(minMax(obtainMin, obtainMax), minMax(verifyMin, verifyMax));
            }
        } else {
            return CredentialSupport.UNSUPPORTED;
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

    CredentialSupport getCredentialSupport(final String realmName, final Class<?> credentialType) {
        final SecurityRealm realm = getRealm(realmName);
        try {
            return realm.getCredentialSupport(credentialType);
        } catch (RealmUnavailableException e) {
            return CredentialSupport.UNSUPPORTED;
        }
    }

    /**
     * Get the current security identity for this domain.
     *
     * @return the current security identity for this domain (not {@code null})
     */
    public SecurityIdentity getCurrentSecurityIdentity() {
        return currentSecurityIdentity.get();
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
            return currentSecurityIdentity.get();
        } finally {
            currentSecurityIdentity.set(newIdentity);
        }
    }

    void setCurrentSecurityIdentity(SecurityIdentity newIdentity) {
        currentSecurityIdentity.set(newIdentity);
    }

    Set<String> mapRoles(SecurityIdentity securityIdentity) {
        Assert.checkNotNullParam("securityIdentity", securityIdentity);

        AuthorizationIdentity identity = securityIdentity.getAuthorizationIdentity();
        Attributes attributes = identity.getAttributes();
        RealmInfo realmInfo = securityIdentity.getRealmInfo();
        RoleDecoder roleDecoder = realmInfo.getRoleDecoder(); // zeroth role mapping, just grab roles from the identity
        Set<String> mappedRoles = roleDecoder.decodeRoles(attributes);
        RoleMapper realmRoleMapper = realmInfo.getRoleMapper();

        // apply the first level mapping, which is based on the role mapper associated with a realm.
        mappedRoles = realmRoleMapper.mapRoles(mappedRoles);

        // apply the second level mapping, which is based on the role mapper associated with this security domain.
        return this.roleMapper.mapRoles(mappedRoles);
    }

    PermissionCollection mapPermissions(SecurityIdentity securityIdentity) {
        Assert.checkNotNullParam("securityIdentity", securityIdentity);
        Principal principal = securityIdentity.getPrincipal();
        Set<String> roles = securityIdentity.getRoles();

        return this.permissionMapper.mapPermissions(principal, roles);
    }

    String getDefaultRealmName() {
        return defaultRealmName;
    }

    NameRewriter getPreRealmRewriter() {
        return preRealmRewriter;
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
        private Supplier<Provider[]> providers = () -> Security.getProviders();

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
            final RealmBuilder realmBuilder = new RealmBuilder(name, realm);
            realms.put(name, realmBuilder);
            return realmBuilder;
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

        public Builder setProviders(final Supplier<Provider[]> providers) {
            assertNotBuilt();
            this.providers = providers;

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
            final HashMap<String, RealmInfo> realmMap = new HashMap<>(realms.size());
            for (RealmBuilder realmBuilder : realms.values()) {
                realmMap.put(realmBuilder.getName(), new RealmInfo(realmBuilder));
            }
            if (!realmMap.containsKey(defaultRealmName)) {
                throw log.realmMapDoesntContainDefault(defaultRealmName);
            }

            assertNotBuilt();
            built = true;

            return new SecurityDomain(this, realmMap);
        }

        private void assertNotBuilt() {
            if (built) {
                throw log.builderAlreadyBuilt();
            }
        }
    }

    /**
     * A builder for a realm within a security domain.
     */
    public static class RealmBuilder {

        private final String name;
        private final SecurityRealm realm;
        private RoleMapper roleMapper = RoleMapper.IDENTITY_ROLE_MAPPER;
        private NameRewriter nameRewriter = NameRewriter.IDENTITY_REWRITER;
        private RoleDecoder roleDecoder = RoleDecoder.EMPTY;

        RealmBuilder(final String name, final SecurityRealm realm) {
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
        public void setRoleMapper(final RoleMapper roleMapper) {
            Assert.checkNotNullParam("roleMapper", roleMapper);
            this.roleMapper = roleMapper;
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
        public void setNameRewriter(final NameRewriter nameRewriter) {
            Assert.checkNotNullParam("nameRewriter", nameRewriter);
            this.nameRewriter = nameRewriter;
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
        public void setRoleDecoder(final RoleDecoder roleDecoder) {
            this.roleDecoder = roleDecoder;
        }
    }
}
