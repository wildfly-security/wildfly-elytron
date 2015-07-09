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
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.Principal;
import java.util.Set;

import org.wildfly.security.auth.server.SecurityDomain;

/**
 * A permission mapper is responsible to enable permission mapping to a {@link SecurityDomain}
 * in order to obtain and check permissions based on an previously authorized identity and any other authorization information (eg.: roles)
 * associated with it.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PermissionMapper {

    /**
     * <p>Returns a <em>read-only</em> {@link PermissionCollection} with all the permissions associated with the given {@link Principal}
     * and roles associated with it (if any).
     *
     * <p>Once returned, client code can use the {@link PermissionCollection#implies(Permission)} to check if a given permission is granted or not
     * to the given principal. Implementors must make sure that the returned collection is immutable.
     *
     * @param principal a principal previously obtained and authenticated from a security domain (not {@code null}
     * @param roles a set of roles associated with the given principal after all role mapping was applied by security domain (may be {@code null}
     * @return a read-only permission collection. If no permission is associated with the given identity, an empty and read-only {@link PermissionCollection} is returned (not {@code null})
     */
    PermissionCollection mapPermissions(Principal principal, Set<String> roles);

    /**
     * A default implementation that does nothing but returns an empty and read-only {@link PermissionCollection}.
     */
    PermissionMapper EMPTY_PERMISSION_MAPPER = (principal, roles) -> Policy.UNSUPPORTED_EMPTY_COLLECTION;
}
