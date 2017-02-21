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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
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
import org.wildfly.security.auth.permission.ChangeRoleMapperPermission;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.event.SecurityPermissionCheckFailedEvent;
import org.wildfly.security.auth.server.event.SecurityPermissionCheckSuccessfulEvent;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.PermissionMappable;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.permission.ElytronPermission;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * A loaded and authenticated security identity.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SecurityIdentity implements PermissionVerifier, PermissionMappable {
    private static final Permission SET_RUN_AS_PERMISSION = ElytronPermission.forName("setRunAsPrincipal");
    private static final Permission PRIVATE_CREDENTIALS_PERMISSION = ElytronPermission.forName("getPrivateCredentials");

    private final SecurityDomain securityDomain;
    private final Principal principal;
    private final AuthorizationIdentity authorizationIdentity;
    private final RealmInfo realmInfo;
    private final Map<String, RoleMapper> roleMappers;
    private final Instant creationTime;
    private final PermissionVerifier verifier;
    private final IdentityCredentials publicCredentials;
    private final IdentityCredentials privateCredentials;
    private final Supplier<SecurityIdentity[]> withSuppliedIdentities;
    private final SecurityIdentity[] withIdentities;

    SecurityIdentity(final SecurityDomain securityDomain, final Principal principal, final RealmInfo realmInfo, final AuthorizationIdentity authorizationIdentity, final Map<String, RoleMapper> roleMappers, final IdentityCredentials publicCredentials, final IdentityCredentials privateCredentials) {
        this.securityDomain = securityDomain;
        this.principal = principal;
        this.realmInfo = realmInfo;
        this.authorizationIdentity = authorizationIdentity;
        this.roleMappers = roleMappers;
        this.creationTime = Instant.now();
        this.verifier = securityDomain.mapPermissions(this);
        this.publicCredentials = publicCredentials;
        this.privateCredentials = privateCredentials;
        this.withSuppliedIdentities = null;
        this.withIdentities = null;
    }

    SecurityIdentity(final SecurityIdentity old, final Map<String, RoleMapper> roleMappers) {
        this.securityDomain = old.securityDomain;
        this.principal = old.principal;
        this.realmInfo = old.realmInfo;
        this.authorizationIdentity = old.authorizationIdentity;
        this.roleMappers = roleMappers;
        this.creationTime = old.creationTime;
        this.verifier = old.verifier;
        this.publicCredentials = old.publicCredentials;
        this.privateCredentials = old.privateCredentials;
        this.withSuppliedIdentities = old.withSuppliedIdentities;
        this.withIdentities = old.withIdentities;
    }

    SecurityIdentity(final SecurityIdentity old, final PermissionVerifier verifier) {
        this.securityDomain = old.securityDomain;
        this.principal = old.principal;
        this.realmInfo = old.realmInfo;
        this.authorizationIdentity = old.authorizationIdentity;
        this.roleMappers = old.roleMappers;
        this.creationTime = old.creationTime;
        this.verifier = verifier;
        this.publicCredentials = old.publicCredentials;
        this.privateCredentials = old.privateCredentials;
        this.withSuppliedIdentities = old.withSuppliedIdentities;
        this.withIdentities = old.withIdentities;
    }

    SecurityIdentity(final SecurityIdentity old, final Credential credential, final boolean isPrivate) {
        this.securityDomain = old.securityDomain;
        this.principal = old.principal;
        this.realmInfo = old.realmInfo;
        this.authorizationIdentity = old.authorizationIdentity;
        this.roleMappers = old.roleMappers;
        this.creationTime = old.creationTime;
        this.verifier = old.verifier;
        this.publicCredentials = isPrivate ? old.publicCredentials : old.publicCredentials.withCredential(credential);
        this.privateCredentials = isPrivate ? old.privateCredentials.withCredential(credential) : old.privateCredentials;
        this.withSuppliedIdentities = old.withSuppliedIdentities;
        this.withIdentities = old.withIdentities;
    }

    SecurityIdentity(final SecurityIdentity old, final IdentityCredentials credentials, final boolean isPrivate) {
        this.securityDomain = old.securityDomain;
        this.principal = old.principal;
        this.realmInfo = old.realmInfo;
        this.authorizationIdentity = old.authorizationIdentity;
        this.roleMappers = old.roleMappers;
        this.creationTime = old.creationTime;
        this.verifier = old.verifier;
        this.publicCredentials = isPrivate ? old.publicCredentials : old.publicCredentials.with(credentials);
        this.privateCredentials = isPrivate ? old.privateCredentials.with(credentials) : old.privateCredentials;
        this.withSuppliedIdentities = old.withSuppliedIdentities;
        this.withIdentities = old.withIdentities;
    }

    SecurityIdentity(final SecurityIdentity old, final Supplier<SecurityIdentity[]> withSuppliedIdentites) {
        this.securityDomain = old.securityDomain;
        this.principal = old.principal;
        this.realmInfo = old.realmInfo;
        this.authorizationIdentity = old.authorizationIdentity;
        this.roleMappers = old.roleMappers;
        this.creationTime = old.creationTime;
        this.verifier = old.verifier;
        this.publicCredentials = old.publicCredentials;
        this.privateCredentials = old.privateCredentials;
        this.withSuppliedIdentities = withSuppliedIdentites;
        this.withIdentities = null;
    }

    SecurityIdentity(final SecurityIdentity old, final SecurityIdentity[] withIdentities) {
        this.securityDomain = old.securityDomain;
        this.principal = old.principal;
        this.realmInfo = old.realmInfo;
        this.authorizationIdentity = old.authorizationIdentity;
        this.roleMappers = old.roleMappers;
        this.creationTime = old.creationTime;
        this.verifier = old.verifier;
        this.publicCredentials = old.publicCredentials;
        this.privateCredentials = old.privateCredentials;
        this.withSuppliedIdentities = null;
        this.withIdentities = withIdentities;
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

    private SecurityIdentity[] establishIdentities() {
        SecurityIdentity[] withIdentities = this.withIdentities != null ? this.withIdentities : withSuppliedIdentities != null ? withSuppliedIdentities.get() : new SecurityIdentity[] {};

        SecurityIdentity[] oldIdentities = new SecurityIdentity[withIdentities.length + 1];
        SecurityDomain securityDomain = this.securityDomain;
        oldIdentities[0] = securityDomain.getAndSetCurrentSecurityIdentity(this);
        for (int i = 0; i < withIdentities.length; i++) {
            SecurityIdentity securityIdentity = withIdentities[i];
            securityDomain = securityIdentity.getSecurityDomain();
            oldIdentities[i + 1] = securityDomain.getAndSetCurrentSecurityIdentity(securityIdentity);
        }

        return oldIdentities;
    }

    private void restoreIdentities(SecurityIdentity[] securityIdentities) {
        for (SecurityIdentity currentIdentity : securityIdentities) {
            currentIdentity.securityDomain.setCurrentSecurityIdentity(currentIdentity);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     */
    public void runAs(Runnable action) {
        if (action == null) return;
        SecurityIdentity[] toRestore = establishIdentities();

        try {
            action.run();
        } finally {
            restoreIdentities(toRestore);
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
        SecurityIdentity[] toRestore = establishIdentities();

        try {
            return action.call();
        } finally {
            restoreIdentities(toRestore);
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
        SecurityIdentity[] toRestore = establishIdentities();

        try {
            return action.run();
        } finally {
            restoreIdentities(toRestore);
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
        SecurityIdentity[] toRestore = establishIdentities();

        try {
            return action.run();
        } catch (RuntimeException | PrivilegedActionException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            restoreIdentities(toRestore);
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
        SecurityIdentity[] toRestore = establishIdentities();

        try {
            return action.run(parameter);
        } finally {
            restoreIdentities(toRestore);
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
        SecurityIdentity[] toRestore = establishIdentities();

        try {
            return action.run(parameter);
        } catch (RuntimeException | PrivilegedActionException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            restoreIdentities(toRestore);
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
        SecurityIdentity[] toRestore = establishIdentities();

        try {
            return action.apply(parameter1, parameter2);
        } finally {
            restoreIdentities(toRestore);
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
        SecurityIdentity[] toRestore = establishIdentities();

        try {
            action.accept(parameter1, parameter2);
        } finally {
            restoreIdentities(toRestore);
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
        SecurityIdentity[] toRestore = establishIdentities();

        try {
            action.accept(parameter1, parameter2);
        } finally {
            restoreIdentities(toRestore);
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
        SecurityIdentity[] toRestore = establishIdentities();

        try {
            return action.get();
        } finally {
            restoreIdentities(toRestore);
        }
    }

    /**
     * Run an action under a series of identities.
     *
     * @param action the action to run
     * @param identities the identities to set up
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     * @throws PrivilegedActionException if the action fails
     */
    public static <T> T runAsAll(PrivilegedExceptionAction<T> action, SecurityIdentity... identities) throws PrivilegedActionException {
        if (action == null) return null;
        int length = identities.length;
        SecurityIdentity[] oldIdentities = new SecurityIdentity[length];
        for (int i = 0; i < length; i++) {
            SecurityIdentity securityIdentity = identities[i];
            SecurityDomain securityDomain = securityIdentity.getSecurityDomain();
            oldIdentities[i] = securityDomain.getAndSetCurrentSecurityIdentity(securityIdentity);
        }
        try {
            return action.run();
        } catch (RuntimeException | PrivilegedActionException e) {
            throw e;
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        } finally {
            for (int i = 0; i < length; i++) {
                SecurityIdentity oldIdentity = oldIdentities[i];
                SecurityDomain securityDomain = oldIdentity.getSecurityDomain();
                securityDomain.setCurrentSecurityIdentity(oldIdentity);
            }
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
     * Attempt to create a new identity that is the same as this identity but with a {@link Supplier<SecurityIdentity[]>} to supply identities that will be associated with all 'run' calls.
     *
     * Any existing individual identities associated with this identity will be dropped.
     *
     * The supplier will be called for each run call so were possible should handle it's own optimisation.
     *
     * @param securityIdentities a {@link Supplier<SecurityIdentity[]>} for identities to be associated with every run call.
     * @return the new identity
     * @throws IllegalArgumentException if the supplied identity
     */
    public SecurityIdentity withSecurityIdentitySupplier(Supplier<SecurityIdentity[]> securityIdentities) {
        Assert.checkNotNullParam("securityIdentities", securityIdentities);
        if (this.withSuppliedIdentities == securityIdentities) {
            return this;
        }

        return new SecurityIdentity(this, securityIdentities);
    }

    /**
     * Attempt to create a new identity that is the same as this identity but with an additional identity from a different
     * security domain that will be associated with all 'run' calls.
     *
     * If a {@link Supplier<SecurityIdentity[]>} has previously been associated with this identity it will be dropped.
     *
     * @param securityIdentity the {@link SecurityIdentity} to also be associated with all run calls made to this identity.
     * @return the new identity
     * @throws IllegalArgumentException if the supplied identity
     */
    public SecurityIdentity withSecurityIdentity(SecurityIdentity securityIdentity) {
        Assert.checkNotNullParam("securityIdentity", securityIdentity);
        if (securityIdentity == this) {
            return this;
        }

        if (securityDomain == securityIdentity.securityDomain) {
            throw log.cantWithSameSecurityDomainDomain();
        }

        List<SecurityIdentity> withIdentities = new ArrayList<>(this.withIdentities.length + 1);
        for (SecurityIdentity currentIdentity : this.withIdentities) {
            if (currentIdentity == securityIdentity) {
                return this;
            }

            if (currentIdentity.securityDomain != securityIdentity.securityDomain) {
                withIdentities.add(currentIdentity);
            }
            withIdentities.add(securityIdentity);
        }

        return new SecurityIdentity(this, withIdentities.toArray(new SecurityIdentity[withIdentities.size()]));
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
     * @throws SecurityException if the caller does not have the {@code setRunAsPrincipal}
     *         {@link ElytronPermission} or if the operation authorization failed for any other reason
     */
    public SecurityIdentity createRunAsIdentity(String name, boolean authorize) throws SecurityException {
        Assert.checkNotNullParam("name", name);
        // rewrite name
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(SET_RUN_AS_PERMISSION);
        }

        final ServerAuthenticationContext context = securityDomain.createNewAuthenticationContext(this, MechanismConfigurationSelector.constantSelector(MechanismConfiguration.EMPTY));
        try {
            if (! (context.importIdentity(this) && context.authorize(name, authorize))) {
                throw log.runAsAuthorizationFailed(principal, new NamePrincipal(name), null);
            }
        } catch (RealmUnavailableException e) {
            throw log.runAsAuthorizationFailed(principal, context.getAuthenticationPrincipal(), e);
        }
        return context.getAuthorizedIdentity();
    }

    /**
     * Attempt to create a new identity that can be used to run as an anonymous user. If the
     * current identity is not authorized to run as an anonymous user, an exception is thrown.
     *
     * @return the new security identity
     * @throws SecurityException if the operation authorization failed for any reason
     */
    public SecurityIdentity createRunAsAnonymous() throws SecurityException {
        return createRunAsAnonymous(true);
    }

    /**
     * Attempt to create a new identity that can be used to run as an anonymous user
     *
     * @param authorize {@code true} to check the current identity is authorized to run as a user
     *        with the given name, {@code false} to just check if the caller has the
     *        {@code setRunAsPermission} {@link RuntimePermission}
     * @return the new security identity
     * @throws SecurityException if the caller does not have the {@code setRunAsPrincipal}
     *         {@link ElytronPermission} or if the operation authorization failed for any other reason
     */
    public SecurityIdentity createRunAsAnonymous(boolean authorize) throws SecurityException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(SET_RUN_AS_PERMISSION);
        }

        final ServerAuthenticationContext context = securityDomain.createNewAuthenticationContext(this, MechanismConfigurationSelector.constantSelector(MechanismConfiguration.EMPTY));
        if (! context.authorizeAnonymous(authorize)) {
            throw log.runAsAuthorizationFailed(principal, AnonymousPrincipal.getInstance(), null);
        }
        return context.getAuthorizedIdentity();
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
        final boolean result = verifier.implies(permission);
        SecurityDomain.safeHandleSecurityEvent(securityDomain,
                result ? new SecurityPermissionCheckSuccessfulEvent(this, permission) : new SecurityPermissionCheckFailedEvent(this, permission));
        return result;
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

    /**
     * Get the public credentials of this identity.
     *
     * @return the public credentials of this identity (not {@code null})
     */
    public IdentityCredentials getPublicCredentials() {
        return publicCredentials;
    }

    /**
     * Convenience method to determine if this identity is anonymous.
     *
     * @return {@code true} if the identity is anonymous, {@code false} otherwise
     */
    public boolean isAnonymous() {
        return principal instanceof AnonymousPrincipal;
    }

    /**
     * Create a new security identity which is the same as this one, but which includes the given credential as a
     * public credential.
     *
     * @param credential the credential (must not be {@code null})
     * @return the new identity
     */
    public SecurityIdentity withPublicCredential(Credential credential) {
        Assert.checkNotNullParam("credential", credential);
        return new SecurityIdentity(this, credential, false);
    }

    /**
     * Create a new security identity which is the same as this one, but which includes the given credentials as
     * public credentials.
     *
     * @param credentials the credential set (must not be {@code null})
     * @return the new identity
     */
    public SecurityIdentity withPublicCredentials(final IdentityCredentials credentials) {
        Assert.checkNotNullParam("credentials", credentials);
        return credentials == IdentityCredentials.NONE ? this : new SecurityIdentity(this, credentials, false);
    }

    /**
     * Create a new security identity which is the same as this one, but which includes the given credential as a
     * private credential.
     *
     * @param credential the credential (must not be {@code null})
     * @return the new identity
     */
    public SecurityIdentity withPrivateCredential(Credential credential) {
        Assert.checkNotNullParam("credential", credential);
        return new SecurityIdentity(this, credential, true);
    }

    /**
     * Create a new security identity which is the same as this one, but which includes the given credentials as
     * private credentials.
     *
     * @param credentials the credential set (must not be {@code null})
     * @return the new identity
     */
    public SecurityIdentity withPrivateCredentials(final IdentityCredentials credentials) {
        Assert.checkNotNullParam("credentials", credentials);
        return credentials == IdentityCredentials.NONE ? this : new SecurityIdentity(this, credentials, true);
    }

    /**
     * Get the private credentials of this identity.  The caller must have the {@code getPrivateCredentials} {@link ElytronPermission}.
     *
     * @return the private credentials of this identity (not {@code null})
     */
    public IdentityCredentials getPrivateCredentials() {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(PRIVATE_CREDENTIALS_PERMISSION);
        }
        return getPrivateCredentialsPrivate();
    }

    IdentityCredentials getPrivateCredentialsPrivate() {
        return privateCredentials;
    }
}
