/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.permission;

import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.ProtectionDomain;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;

/**
 * An interface for objects that can verify permissions.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@FunctionalInterface
public interface PermissionVerifier {
    /**
     * Determine if the permission is verified by this object.
     *
     * @param permission the permission to verify (must not be {@code null})
     * @return {@code true} if the permission is implied by this verifier, {@code false} otherwise
     */
    boolean implies(Permission permission);

    /**
     * Return a new verifier which implies permissions which are implied both by this verifier and by the given verifier.
     *
     * @param other the other verifier (must not be {@code null})
     * @return the new permission verifier (not {@code null})
     */
    default PermissionVerifier and(PermissionVerifier other) {
        Assert.checkNotNullParam("other", other);
        return permission -> implies(permission) && other.implies(permission);
    }

    /**
     * Return a new verifier which implies permissions which are implied either by this verifier or by the given verifier.
     *
     * @param other the other verifier (must not be {@code null})
     * @return the new permission verifier (not {@code null})
     */
    default PermissionVerifier or(PermissionVerifier other) {
        Assert.checkNotNullParam("other", other);
        return permission -> implies(permission) || other.implies(permission);
    }

    /**
     * Return a new verifier which implies permissions which are implied by only one of this verifier or the given verifier.
     *
     * @param other the other verifier (must not be {@code null})
     * @return the new permission verifier (not {@code null})
     */
    default PermissionVerifier xor(PermissionVerifier other) {
        Assert.checkNotNullParam("other", other);
        return permission -> implies(permission) ^ other.implies(permission);
    }

    /**
     * Return a new verifier which implies the opposite of this verifier.
     *
     * @return the new permission verifier (not {@code null})
     */
    default PermissionVerifier not() {
        return permission -> ! implies(permission);
    }

    /**
     * Return a new verifier which implies permissions which are implied by this verifier but not the given verifier.
     *
     * @param other the other verifier (must not be {@code null})
     * @return the new permission verifier (not {@code null})
     */
    default PermissionVerifier unless(PermissionVerifier other) {
        Assert.checkNotNullParam("other", other);
        return permission -> implies(permission) && ! other.implies(permission);
    }

    /**
     * Check a permission, throwing an exception if the permission is not implied.
     *
     * @param permission the permission to check (must not be {@code null})
     * @throws SecurityException if the permission is not implied
     */
    default void checkPermission(Permission permission) throws SecurityException {
        Assert.checkNotNullParam("permission", permission);
        if (! implies(permission)) {
            throw ElytronMessages.log.permissionCheckFailed(permission, this);
        }
    }

    /**
     * Get a permission verifier for a single permission.
     *
     * @param permission the permission (must not be {@code null})
     * @return the verifier (not {@code null})
     */
    static PermissionVerifier from(Permission permission) {
        Assert.checkNotNullParam("permission", permission);
        return permission instanceof PermissionVerifier ? (PermissionVerifier) permission : permission::implies;
    }

    /**
     * Get a permission verifier for a permission collection.
     *
     * @param permissionCollection the permission collection (must not be {@code null})
     * @return the verifier (not {@code null})
     */
    static PermissionVerifier from(PermissionCollection permissionCollection) {
        Assert.checkNotNullParam("permissionCollection", permissionCollection);
        return permissionCollection instanceof PermissionVerifier ? (PermissionVerifier) permissionCollection : permissionCollection::implies;
    }

    /**
     * Get a permission verifier for a protection domain.
     *
     * @param protectionDomain the protection domain (must not be {@code null})
     * @return the verifier (not {@code null})
     */
    static PermissionVerifier from(ProtectionDomain protectionDomain) {
        Assert.checkNotNullParam("protectionDomain", protectionDomain);
        return protectionDomain instanceof PermissionVerifier ? (PermissionVerifier) protectionDomain : protectionDomain::implies;
    }

    /**
     * Get a permission verifier for a policy's view of a protection domain.
     *
     * @param policy the policy (must not be {@code null})
     * @param protectionDomain the protection domain (must not be {@code null})
     * @return the verifier (not {@code null})
     */
    static PermissionVerifier from(Policy policy, ProtectionDomain protectionDomain) {
        Assert.checkNotNullParam("policy", policy);
        Assert.checkNotNullParam("protectionDomain", protectionDomain);
        return permission -> policy.implies(protectionDomain, permission);
    }

    /**
     * Convert this verifier a permission collection which implies everything this verifier implies.  If this instance
     * is already a {@code PermissionCollection} instance, then this instance may be cast and returned.  Otherwise,
     * this method may return a new, read-only collection, which cannot be iterated.
     *
     * @return the permission collection (not {@code null})
     */
    default PermissionCollection toPermissionCollection() {
        if (this instanceof PermissionCollection) {
            return (PermissionCollection) this;
        } else {
            return new PermissionVerifierPermissionCollection(this);
        }
    }

    /**
     * A verifier which implies no permissions.
     */
    PermissionVerifier NONE = permission -> false;

    /**
     * A verifier which implies all permissions.
     */
    PermissionVerifier ALL = permission -> true;
}
