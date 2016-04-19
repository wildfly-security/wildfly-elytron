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

package org.wildfly.security.auth.server;

import static org.wildfly.security._private.ElytronMessages.log;

import java.security.Permission;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.ObjIntConsumer;
import java.util.function.Supplier;

import org.wildfly.common.Assert;
import org.wildfly.security.ParametricPrivilegedAction;
import org.wildfly.security.ParametricPrivilegedExceptionAction;
import org.wildfly.security.auth.client.PeerIdentity;
import org.wildfly.security.auth.permission.ChangeRoleMapperPermission;
import org.wildfly.security.auth.permission.RunAsPrincipalPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.event.RealmIdentityFailedAuthorizationEvent;
import org.wildfly.security.auth.server.event.RealmIdentitySuccessfulAuthorizationEvent;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.permission.ElytronPermission;

/**
 * A loaded and authenticated security identity.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SecurityIdentity implements PermissionVerifier {
    static final PeerIdentity[] NO_PEER_IDENTITIES = new PeerIdentity[0];
    private static final Permission SET_RUN_AS_PERMISSION = ElytronPermission.forName("setRunAsPrincipal");

    private final SecurityDomain securityDomain;
    private final Principal principal;
    private final AuthorizationIdentity authorizationIdentity;
    private final RealmInfo realmInfo;
    private final Map<String, RoleMapper> roleMappers;
    private final PeerIdentity[] peerIdentities;
    private final Instant creationTime;
    private final PermissionVerifier verifier;

    SecurityIdentity(final SecurityDomain securityDomain, final Principal principal, final RealmInfo realmInfo, final AuthorizationIdentity authorizationIdentity, final Map<String, RoleMapper> roleMappers) {
        this(securityDomain, principal, realmInfo, authorizationIdentity, roleMappers, NO_PEER_IDENTITIES);
    }

    SecurityIdentity(final SecurityDomain securityDomain, final Principal principal, final RealmInfo realmInfo, final AuthorizationIdentity authorizationIdentity, final Map<String, RoleMapper> roleMappers, final PeerIdentity[] peerIdentities) {
        this.securityDomain = securityDomain;
        this.principal = principal;
        this.realmInfo = realmInfo;
        this.authorizationIdentity = authorizationIdentity;
        this.roleMappers = roleMappers;
        this.peerIdentities = peerIdentities;
        this.creationTime = Instant.now();
        this.verifier = securityDomain.mapPermissions(this);
    }

    SecurityIdentity(final SecurityIdentity old, final PeerIdentity[] newPeerIdentities) {
        this.securityDomain = old.securityDomain;
        this.principal = old.principal;
        this.realmInfo = old.realmInfo;
        this.authorizationIdentity = old.authorizationIdentity;
        this.roleMappers = old.roleMappers;
        this.peerIdentities = newPeerIdentities;
        this.creationTime = old.creationTime;
        this.verifier = old.verifier;
    }

    SecurityIdentity(final SecurityIdentity old, final Map<String, RoleMapper> roleMappers) {
        this.securityDomain = old.securityDomain;
        this.principal = old.principal;
        this.realmInfo = old.realmInfo;
        this.authorizationIdentity = old.authorizationIdentity;
        this.roleMappers = roleMappers;
        this.peerIdentities = old.peerIdentities;
        this.creationTime = old.creationTime;
        this.verifier = old.verifier;
    }

    SecurityIdentity(final SecurityIdentity old, final PermissionVerifier verifier) {
        this.securityDomain = old.securityDomain;
        this.principal = old.principal;
        this.realmInfo = old.realmInfo;
        this.authorizationIdentity = old.authorizationIdentity;
        this.roleMappers = old.roleMappers;
        this.peerIdentities = old.peerIdentities;
        this.creationTime = old.creationTime;
        this.verifier = verifier;
    }

    SecurityDomain getSecurityDomain() {
        return securityDomain;
    }

    RealmInfo getRealmInfo() {
        return this.realmInfo;
    }

    AuthorizationIdentity getAuthorizationIdentity() {
        return authorizationIdentity;
    }

    PeerIdentity[] getPeerIdentities() {
        return peerIdentities;
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     */
    public void runAs(Runnable action) {
        if (action == null) return;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            PeerIdentity.runAsAll(action, peerIdentities);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     * @throws Exception if the action fails
     */
    public <T> T runAs(Callable<T> action) throws Exception {
        if (action == null) return null;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return PeerIdentity.runAsAll(action, peerIdentities);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     */
    public <T> T runAs(PrivilegedAction<T> action) {
        if (action == null) return null;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return PeerIdentity.runAsAll(action, peerIdentities);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     * @throws PrivilegedActionException if the action fails
     */
    public <T> T runAs(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        if (action == null) return null;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return PeerIdentity.runAsAll(action, peerIdentities);
        } catch (RuntimeException | PrivilegedActionException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the action result (may be {@code null})
     */
    public <T, P> T runAs(P parameter, ParametricPrivilegedAction<T, P> action) {
        if (action == null) return null;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return PeerIdentity.runAsAll(parameter, action, peerIdentities);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the action result (may be {@code null})
     * @throws PrivilegedActionException if the action fails
     */
    public <T, P> T runAs(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        if (action == null) return null;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return PeerIdentity.runAsAll(parameter, action, peerIdentities);
        } catch (RuntimeException | PrivilegedActionException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <R> the action return type
     * @param <T> the action parameter type
     * @return the action result (may be {@code null})
     */
    public <T, R> R runAsFunction(Function<T, R> action, T parameter) {
        if (action == null) return null;
        return runAsFunction(Function::apply, action, parameter);
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param action the action to run
     * @param <R> the action return type
     * @param <T> the action first parameter type
     * @param <U> the action second parameter type
     * @return the action result (may be {@code null})
     */
    public <T, U, R> R runAsFunction(BiFunction<T, U, R> action, T parameter1, U parameter2) {
        if (action == null) return null;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return PeerIdentity.runAsAllFunction(parameter1, parameter2, action, peerIdentities);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <T> the action parameter type
     */
    public <T> void runAsConsumer(Consumer<T> action, T parameter) {
        if (action == null) return;
        runAsConsumer(Consumer::accept, action, parameter);
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param action the action to run
     * @param <T> the action first parameter type
     * @param <U> the action second parameter type
     */
    public <T, U> void runAsConsumer(BiConsumer<T, U> action, T parameter1, U parameter2) {
        if (action == null) return;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            PeerIdentity.runAsAllConsumer(parameter1, parameter2, action, peerIdentities);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param action the action to run
     * @param <T> the action first parameter type
     */
    public <T> void runAsObjIntConsumer(ObjIntConsumer<T> action, T parameter1, int parameter2) {
        if (action == null) return;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            PeerIdentity.runAsAllObjIntConsumer(parameter1, parameter2, action, peerIdentities);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     */
    public <T> T runAsSupplier(Supplier<T> action) {
        if (action == null) return null;
        final SecurityDomain securityDomain = this.securityDomain;
        final SecurityIdentity old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return PeerIdentity.runAsAllSupplier(action, peerIdentities);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    /**
     * Get the roles associated with this identity.
     *
     * @return the roles associated with this identity
     */
    public Roles getRoles() {
        return this.securityDomain.mapRoles(this);
    }

    /**
     * Get the mapped roles associated with this identity.  If no role mapping exists for the given category, an
     * empty role set is returned.
     *
     * @param category the role mapping category
     * @return the category roles
     */
    public Roles getRoles(String category) {
        return getRoles(category, false);
    }

    /**
     * Get the mapped roles associated with this identity.
     *
     * @param category the role mapping category
     * @param fallbackToDefault {@code true} if the default roles associated with this identity should be returned if no
     *                          role mapping exists for the given category, {@code false} otherwise
     * @return the category roles
     */
    public Roles getRoles(String category, boolean fallbackToDefault) {
        final RoleMapper roleMapper = roleMappers.get(category);
        return roleMapper == null ? (fallbackToDefault ? getRoles() : Roles.NONE) : roleMapper.mapRoles(securityDomain.mapRoles(this));
    }

    /**
     * Attempt to create a new identity which replaces a role mapper category on the current identity.  If the given role
     * mapper is already set on the current identity, the current identity is returned.
     *
     * @param category the category name
     * @param roleMapper the role mapper to use
     * @return the new identity
     * @throws SecurityException if the calling class is not granted the {@link ChangeRoleMapperPermission} for the given
     *      category name
     */
    public SecurityIdentity withRoleMapper(String category, RoleMapper roleMapper) {
        Assert.checkNotNullParam("category", category);
        Assert.checkNotNullParam("roleMapper", roleMapper);
        final Map<String, RoleMapper> roleMappers = this.roleMappers;
        final RoleMapper existingRoleMapper = roleMappers.get(category);
        if (existingRoleMapper == roleMapper) {
            // identical
            return this;
        }
        // it's a change of some sort
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new ChangeRoleMapperPermission(category));
        }
        // authorized; next see if we can use a memory-efficient collection
        final Map<String, RoleMapper> newMap;
        if (roleMappers.isEmpty() || roleMappers.size() == 1 && roleMappers.keySet().iterator().next().equals(category)) {
            newMap = Collections.singletonMap(category, roleMapper);
        } else {
            newMap = new HashMap<>(roleMappers);
            newMap.put(category, roleMapper);
        }
        return new SecurityIdentity(this, newMap);
    }

    /**
     * Attempt to create a new identity that can be used to run as a user with the given name. If the
     * current identity is not authorized to run as a user with the given name, an exception is thrown.
     *
     * @param name the name to attempt to run as
     * @return the new security identity
     * @throws SecurityException if the operation authorization failed for any reason
     */
    public SecurityIdentity createRunAsIdentity(String name) throws SecurityException {
        return createRunAsIdentity(name, true);
    }

    /**
     * Attempt to create a new identity that can be used to run as a user with the given name.
     *
     * @param name the name to attempt to run as
     * @param authorize {@code true} to check the current identity is authorized to run as a user
     *        with the given name, {@code false} to just check if the caller has the
     *        {@code setRunAsPermission} {@link RuntimePermission}
     * @return the new security identity
     * @throws SecurityException if the caller does not have the {@code setRunAsPermission}
     *         {@link RuntimePermission} or if the operation authorization failed for any other reason
     */
    public SecurityIdentity createRunAsIdentity(String name, boolean authorize) throws SecurityException {
        Assert.checkNotNullParam("name", name);
        // rewrite name
        final SecurityDomain domain = this.securityDomain;
        name = domain.getPreRealmRewriter().rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }
        String realmName = domain.mapRealmName(name, null, null);
        Principal principal = new NamePrincipal(name);
        if (this.principal.equals(principal)) {
            // it's the same identity; just succeed
            return this;
        }
        RealmInfo realmInfo = domain.getRealmInfo(realmName);
        name = domain.getPostRealmRewriter().rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }
        name = realmInfo.getNameRewriter().rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }
        if (authorize) {
            final RunAsPrincipalPermission permission = new RunAsPrincipalPermission(name);
            if (! implies(permission)) {
                SecurityRealm.safeHandleRealmEvent(realmInfo.getSecurityRealm(), new RealmIdentityFailedAuthorizationEvent(authorizationIdentity, this.principal, principal));
                throw log.unauthorizedRunAs(this.principal, principal, permission);
            }
        }
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(SET_RUN_AS_PERMISSION);
        }
        try {
            final SecurityRealm securityRealm = realmInfo.getSecurityRealm();
            final RealmIdentity realmIdentity = securityRealm.getRealmIdentity(name, null, null);
            final AuthorizationIdentity newAuthorizationIdentity = realmIdentity.getAuthorizationIdentity();
            SecurityRealm.safeHandleRealmEvent(securityRealm, new RealmIdentitySuccessfulAuthorizationEvent(this.authorizationIdentity, this.principal, principal));
            try {
                return securityDomain.transform(new SecurityIdentity(domain, principal, realmInfo, newAuthorizationIdentity, roleMappers));
            } finally {
                realmIdentity.dispose();
            }
        } catch (RealmUnavailableException ex) {
            throw log.runAsAuthorizationFailed(this.principal, principal, ex);
        }
    }

    /**
     * Create a new security identity which is the same as this one, but which also establishes the given peer identity
     * in addition to the security identity.
     *
     * @param peerIdentity the peer identity
     * @return the new security identity
     */
    public SecurityIdentity withPeerIdentity(PeerIdentity peerIdentity) {
        if (peerIdentity == null) return this;
        PeerIdentity[] peerIdentities = this.peerIdentities;
        final int length = peerIdentities.length;
        for (int i = 0; i < length; i++) {
            if (peerIdentities[i].isSamePeerIdentityContext(peerIdentity)) {
                PeerIdentity[] newPeerIdentities = peerIdentities.clone();
                newPeerIdentities[i] = peerIdentity;
                return new SecurityIdentity(this, newPeerIdentities);
            }
        }
        PeerIdentity[] newPeerIdentities = Arrays.copyOf(peerIdentities, length + 1);
        newPeerIdentities[length] = peerIdentity;
        return new SecurityIdentity(this, newPeerIdentities);
    }

    /**
     * Create a new security identity which is the same as this one, but which limits authorization privileges to the
     * intersection of the current privileges and the given verifier.
     *
     * @param verifier the restricted verifier (must not be {@code null})
     * @return the restricted identity
     */
    public SecurityIdentity intersectWith(PermissionVerifier verifier) {
        Assert.checkNotNullParam("verifier", verifier);
        return new SecurityIdentity(this, this.verifier.and(verifier));
    }

    public boolean implies(final Permission permission) {
        // TODO: authorization audit goes here
        return verifier.implies(permission);
    }

    /**
     * Get the attributes associated with this identity.
     *
     * @return a read-only instance of {@link Attributes} with all attributes associated with this identity
     */
    public Attributes getAttributes() {
        return this.authorizationIdentity.getAttributes().asReadOnly();
    }

    /**
     * Get the principal of this identity.
     *
     * @return the principal of this identity
     */
    public Principal getPrincipal() {
        return principal;
    }

    /**
     * Get the creation time of this identity, which is the time that the initial authentication occurred.
     *
     * @return the creation time of this identity (not {@code null})
     */
    public Instant getCreationTime() {
        return creationTime;
    }
}
