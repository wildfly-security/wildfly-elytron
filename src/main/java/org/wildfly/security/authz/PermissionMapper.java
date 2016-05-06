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
package org.wildfly.security.authz;

import java.security.Permission;

import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * A permission mapper is responsible to enable permission mapping to a {@link SecurityDomain}
 * in order to obtain and check permissions based on an previously authorized identity and any other authorization information (eg.: roles)
 * associated with it.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@FunctionalInterface
public interface PermissionMapper {

    /**
     * <p>Returns a {@link PermissionVerifier} with all the permissions associated with the given information.
     *
     * <p>Once returned, client code can use the {@link PermissionVerifier#implies(Permission)} to check if a given permission is granted or not
     * to the given principal. Implementors must make sure that the returned collection is immutable.
     *
     * @param permissionMappable the object to which permissions can be mapped (must not be {@code null})
     * @param roles a set of effective roles after all role mapping was applied by security domain (may be {@code null})
     * @return a permission verifier (not {@code null})
     */
    PermissionVerifier mapPermissions(PermissionMappable permissionMappable, Roles roles);

    /**
     * Returns a new mapper where the {@link PermissionVerifier} created by this {@link PermissionMapper} is combined with the
     * {@code PermissionVerifier} of the {@code other} {@code PermissionMapper} using 'and'.
     *
     * @param other the other {@link PermissionMapper} to combine with this {@link PermissionMapper}
     * @return the combined {@link PermissionMapper}
     */
    default PermissionMapper and(final PermissionMapper other) {
        return (p, r) -> mapPermissions(p, r).and(other.mapPermissions(p, r));
    }

    /**
     * Returns a new mapper where the {@link PermissionVerifier} created by this {@link PermissionMapper} is combined with the
     * {@code PermissionVerifier} of the {@code other} {@code PermissionMapper} using 'or'.
     *
     * @param other the other {@link PermissionMapper} to combine with this {@link PermissionMapper}
     * @return the combined {@link PermissionMapper}
     */
    default PermissionMapper or(final PermissionMapper other) {
        return (p, r) -> mapPermissions(p, r).or(other.mapPermissions(p, r));
    }

    /**
     * Returns a new mapper where the {@link PermissionVerifier} created by this {@link PermissionMapper} is combined with the
     * {@code PermissionVerifier} of the {@code other} {@code PermissionMapper} using 'xor'.
     *
     * @param other the other {@link PermissionMapper} to combine with this {@link PermissionMapper}
     * @return the combined {@link PermissionMapper}
     */
    default PermissionMapper xor(final PermissionMapper other) {
        return (p, r) -> mapPermissions(p, r).xor(other.mapPermissions(p, r));
    }

    /**
     * Returns a new mapper where the {@link PermissionVerifier} created by this {@link PermissionMapper} is combined with the
     * {@code PermissionVerifier} of the {@code other} {@code PermissionMapper} using 'unless'.
     *
     * @param other the other {@link PermissionMapper} to combine with this {@link PermissionMapper}
     * @return the combined {@link PermissionMapper}
     */
    default PermissionMapper unless(final PermissionMapper other) {
        return (p, r) -> mapPermissions(p, r).unless(other.mapPermissions(p, r));
    }

    /**
     * A default implementation that does nothing but returns an empty and read-only {@link PermissionVerifier}.
     */
    PermissionMapper EMPTY_PERMISSION_MAPPER = (permissionMappable, roles) -> PermissionVerifier.NONE;
}
