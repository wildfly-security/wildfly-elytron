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

package org.wildfly.security.auth.client;

import java.util.Set;

import org.wildfly.security.authz.Attributes;

/**
 * A remote interface to a peer identity.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface PeerIdentityHandle {
    /**
     * Get the peer identity roles.
     *
     * @return the peer identity role set
     */
    Set<String> getPeerRoles();

    /**
     * Determine whether the peer identity has a given role name.
     *
     * @param roleName the role name
     * @return {@code true} if the peer identity has the role, {@code false} otherwise
     */
    boolean hasPeerRole(String roleName);

    /**
     * Get the attribute set for the peer identity.
     *
     * @return the peer identity attributes
     */
    Attributes getPeerAttributes();

    /**
     * Get a specific attribute value for the peer identity.
     *
     * @param key the attribute name
     * @return the attribute value entry, or {@code null} if there is no matching entry
     */
    Attributes.Entry getPeerAttribute(String key);

    /**
     * An optional notification called at the start of identity-to-thread association.  If this method fails,
     * association will not occur.
     */
    default void preAssociate() {}

    /**
     * An optional notification called at the end of identity-to-thread association.  Any failure of this method
     * will be ignored.
     */
    default void postAssociate() {}
}
