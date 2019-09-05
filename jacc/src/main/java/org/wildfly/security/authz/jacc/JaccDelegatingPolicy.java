/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.authz.jacc;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.Roles;

import javax.security.jacc.EJBMethodPermission;
import javax.security.jacc.EJBRoleRefPermission;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.WebResourcePermission;
import javax.security.jacc.WebRoleRefPermission;
import javax.security.jacc.WebUserDataPermission;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static java.lang.System.getSecurityManager;
import static java.security.AccessController.doPrivileged;
import static org.wildfly.security.authz.jacc.ElytronMessages.log;

/**
 * <p>A {@link Policy} implementation that knows how to process JACC permissions.
 *
 * <p>Elytron's JACC implementation is fully integrated with the Permission Mapping API, which allows users to specify custom permissions
 * for a {@link SecurityDomain} and its identities by configuring a {@link org.wildfly.security.authz.PermissionMapper}. In this case,
 * the permissions are evaluated considering both JACC-specific permissions (as defined by the specs) and also the ones associated with the current
 * and authorized {@link SecurityIdentity}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JaccDelegatingPolicy extends Policy {

    private static final PrivilegedAction<Policy> GET_POLICY_ACTION = Policy::getPolicy;
    private static final String ANY_AUTHENTICATED_USER_ROLE = "**";

    private final Policy delegate;
    private final Set<Class<? extends Permission>> supportedPermissionTypes = new HashSet<>();

    /**
     * Create a new instance. In this case, the current policy will be automatically obtained and used to delegate method
     * calls.
     */
    public JaccDelegatingPolicy() {
        this(getSecurityManager() != null ? doPrivileged(GET_POLICY_ACTION) : Policy.getPolicy());
    }

    /**
     * Create a new instance based on the given {@code delegate}.
     *
     * @param delegate the policy that will be used to delegate method calls
     */
    public JaccDelegatingPolicy(Policy delegate) {
        this.delegate = Assert.checkNotNullParam("delegate", delegate);
        this.supportedPermissionTypes.add(WebResourcePermission.class);
        this.supportedPermissionTypes.add(WebRoleRefPermission.class);
        this.supportedPermissionTypes.add(WebUserDataPermission.class);
        this.supportedPermissionTypes.add(EJBMethodPermission.class);
        this.supportedPermissionTypes.add(EJBRoleRefPermission.class);
    }

    @Override
    public boolean implies(ProtectionDomain domain, Permission permission) {
        try {
            if (isJaccPermission(permission)) {
                ElytronPolicyConfiguration policyConfiguration = ElytronPolicyConfigurationFactory.getCurrentPolicyConfiguration();

                if (impliesExcludedPermission(permission, policyConfiguration)) {
                    return false;
                }

                if (impliesUncheckedPermission(permission, policyConfiguration)) {
                    return true;
                }

                if (impliesRolePermission(domain, permission, policyConfiguration)) {
                    return true;
                }

                // Here we check the permissions mapped to the current identity.
                // We only perform this check for JACC permissions otherwise we intercept all
                // SecurityManager checks.
                if (impliesIdentityPermission(permission)) {
                    return true;
                }
            }

        } catch (Exception e) {
            log.authzFailedToCheckPermission(domain, permission, e);
        }

        return this.delegate.implies(domain, permission);
    }

    @Override
    public PermissionCollection getPermissions(ProtectionDomain domain) {
        final PermissionCollection delegatePermissions = delegate.getPermissions(domain);
        return new PermissionCollection() {
            @Override
            public void add(Permission permission) {
                if (isJaccPermission(permission)) {
                    throw ElytronMessages.log.readOnlyPermissionCollection();
                } else {
                    delegatePermissions.add(permission);
                }
            }

            @Override
            public boolean implies(Permission permission) {
                if (!isJaccPermission(permission) && delegatePermissions.implies(permission)) {
                    return true;
                }

                return JaccDelegatingPolicy.this.implies(domain, permission);
            }

            @Override
            public Enumeration<Permission> elements() {
                return delegatePermissions.elements();
            }
        };
    }

    @Override
    public PermissionCollection getPermissions(CodeSource codeSource) {
        return codeSource == null ? Policy.UNSUPPORTED_EMPTY_COLLECTION : getPermissions(new ProtectionDomain(codeSource, null));
    }

    @Override
    public void refresh() {
        //TODO: we can probably provide some caching for permissions and checks. In this case, we can use this method to refresh the cache.
        this.delegate.refresh();
    }

    private boolean impliesIdentityPermission(Permission permission) {
        SecurityIdentity actualIdentity = getCurrentSecurityIdentity();
        return actualIdentity != null && actualIdentity.implies(permission);
    }

    private SecurityIdentity getCurrentSecurityIdentity() {
        try {
            return (SecurityIdentity) PolicyContext.getContext(SecurityIdentityHandler.KEY);
        } catch (Exception cause) {
            log.authzCouldNotObtainSecurityIdentity(cause);
        }

        return null;
    }

    private void extractRolesFromCurrentIdentity(Set<String> roles) throws PolicyContextException, ClassNotFoundException {
        SecurityIdentity identity = getCurrentSecurityIdentity();

        if (identity != null) {
            Roles identityRoles = identity.getRoles();

            if (identityRoles != null) {
                for (String roleName : identityRoles) {
                    roles.add(roleName);
                }
            }
        }
    }

    private void extractRolesFromProtectionDomain(ProtectionDomain domain, Set<String> roles) {
        Principal[] domainPrincipals = domain.getPrincipals();

        if (domainPrincipals != null) {
            for (Principal principal : domainPrincipals) {
                roles.add(principal.getName());
            }
        }
    }

    private boolean impliesRolePermission(ProtectionDomain domain, Permission permission, ElytronPolicyConfiguration policyConfiguration) throws PolicyContextException, ClassNotFoundException {
        Set<String> roles = new HashSet<>();

        // keep JACC behavior where roles are obtained as Principal instances from a ProtectionDomain
        extractRolesFromProtectionDomain(domain, roles);

        // obtain additional roles from the current authenticated identity.
        // in this case the a RoleMapper will be used to map roles from the authenticated identity
        extractRolesFromCurrentIdentity(roles);

        roles.add(ANY_AUTHENTICATED_USER_ROLE);

        Map<String, Permissions> rolePermissions = policyConfiguration.getRolePermissions();

        synchronized (rolePermissions) {
            for (String roleName : roles) {
                Permissions permissions = rolePermissions.get(roleName);

                if (permissions != null) {
                    if (permissions.implies(permission)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private boolean impliesUncheckedPermission(Permission permission, ElytronPolicyConfiguration policyConfiguration) {
        Permissions uncheckedPermissions = policyConfiguration.getUncheckedPermissions();

        synchronized (uncheckedPermissions) {
            return uncheckedPermissions.implies(permission);
        }
    }

    private boolean impliesExcludedPermission(Permission permission, ElytronPolicyConfiguration policyConfiguration) {
        Permissions excludedPermissions = policyConfiguration.getExcludedPermissions();

        synchronized (excludedPermissions) {
            return excludedPermissions.implies(permission);
        }
    }

    private boolean isJaccPermission(Permission permission) {
        return this.supportedPermissionTypes.contains(permission.getClass());
    }
}

