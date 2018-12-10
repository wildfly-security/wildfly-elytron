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

package org.wildfly.security.authz;

import java.security.Principal;
import java.time.Instant;

import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.auth.server.IdentityCredentials;

/**
 * An entity to which permissions can be mapped.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface PermissionMappable {
    /**
     * Get the attributes of this entity.
     *
     * @return the attributes of this entity (must not be {@code null})
     */
    default Attributes getAttributes() {
        return Attributes.EMPTY;
    }

    /**
     * Get the principal of this entity.
     *
     * @return the principal of this entity (must not be {@code null})
     */
    default Principal getPrincipal() {
        return AnonymousPrincipal.getInstance();
    }

    /**
     * Get the creation time of this entity (if known).
     *
     * @return the creation time of this entity, or {@code null} if it cannot be determined
     */
    default Instant getCreationTime() {
        return null;
    }

    /**
     * Get the public credentials of this entity.
     *
     * @return the public credentials (must not be {@code null})
     */
    default IdentityCredentials getPublicCredentials() {
        return IdentityCredentials.NONE;
    }
}
