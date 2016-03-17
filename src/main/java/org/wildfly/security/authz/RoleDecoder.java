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

package org.wildfly.security.authz;

import java.util.HashSet;

/**
 * A decoder to extract role information from an identity's attributes.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface RoleDecoder {

    /**
     * A key whose value is the string "Roles", to provide a standard/default location at which roles may be found.
     */
    String KEY_ROLES = "Roles";

    /**
     * Decode the role set from the given attributes.
     *
     * @param attributes the attributes
     * @return the role set (must not be {@code null})
     */
    Roles decodeRoles(Attributes attributes);

    /**
     * A role decoder which decodes no roles.
     */
    RoleDecoder EMPTY = attributes -> Roles.NONE;

    /**
     * A role decoder which always decodes roles from the attribute called "Roles".
     */
    RoleDecoder DEFAULT = simple(KEY_ROLES);

    /**
     * Create a simple role decoder which returns the values of the given attribute.
     *
     * @param attribute the attribute
     * @return the roles
     */
    static RoleDecoder simple(String attribute) {
        return attributes -> {
            final Attributes.Entry entry = attributes.get(attribute);
            return entry.isEmpty() ? Roles.NONE : entry instanceof Attributes.SetEntry ? Roles.fromSet((Attributes.SetEntry) entry) : Roles.fromSet(new HashSet<>(entry));
        };
    }
}
