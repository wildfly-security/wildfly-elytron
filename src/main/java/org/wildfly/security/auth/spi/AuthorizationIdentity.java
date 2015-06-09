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

package org.wildfly.security.auth.spi;

import java.security.Principal;
import java.util.Collections;
import java.util.Set;

import org.wildfly.security.auth.principal.AnonymousPrincipal;

/**
 * A realm's authorization identity.  Objects of this class represent an active identity which may be examined for
 * authorization decisions.  Since there is no upper bound in the lifespan of instances of this class, they should
 * not retain references to scarce resources like database connections or file handles.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface AuthorizationIdentity {

    /**
     * Get the {@link Principal} for this identity, or {@code null} if there is none.
     *
     * @return the {@link Principal} for this identity
     */
    Principal getPrincipal();

    /**
     * <p>Get the roles in their raw form for this identity. Roles are represented as {@link String} values where
     * each value is related with the name of a role.</p>
     *
     * <p>The raw form of a role is usually the same that came from the underlying identity store (eg.: database or LDAP server).
     * Additional mapping may be applied later by a specific {@link org.wildfly.security.authz.RoleMapper} associated with the
     * {@link SecurityRealm} or {@link org.wildfly.security.auth.login.SecurityDomain} from where this identity was created.</p>
     *
     * @return A string set containing the roles for this identity or an empty set if this identity has no roles.
     */
    Set<String> getRoles();

    /**
     * The anonymous authorization identity.
     */
    AuthorizationIdentity ANONYMOUS = new AuthorizationIdentity() {
        public Principal getPrincipal() {
            return AnonymousPrincipal.getInstance();
        }

        public Set<String> getRoles() {
            return Collections.emptySet();
        }
    };
}
