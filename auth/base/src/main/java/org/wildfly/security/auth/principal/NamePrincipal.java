/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.principal;

import java.io.Serializable;
import java.security.Principal;

import org.wildfly.common.Assert;

/**
 * A principal which is comprised of a simple {@code String} name.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class NamePrincipal implements Principal, Serializable {

    private static final long serialVersionUID = -6380283371738985125L;

    /**
     * @serial The principal name.
     */
    private final String name;

    /**
     * Construct a new instance.
     *
     * @param name the principal name
     */
    public NamePrincipal(final String name) {
        Assert.checkNotNullParam("name", name);
        this.name = name;
    }

    /**
     * Get the principal name.
     *
     * @return the principal name
     */
    public String getName() {
        return name;
    }

    /**
     * Get the hash code of this principal.
     *
     * @return the hash code of this principal
     */
    public int hashCode() {
        return name.hashCode();
    }

    /**
     * Determine whether this principal is equal to the given object.
     *
     * @param obj the object
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public boolean equals(final Object obj) {
        return obj instanceof NamePrincipal && equals((NamePrincipal) obj);
    }

    /**
     * Determine whether this principal is equal to the given object.
     *
     * @param obj the object
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public boolean equals(final NamePrincipal obj) {
        return obj != null && name.equals(obj.name);
    }

    /**
     * Get a string representation of this principal.
     *
     * @return the string representation of this principal
     */
    public String toString() {
        return name;
    }

    /**
     * Attempt to convert the given principal to a {@code NamePrincipal}.
     *
     * @param principal the original principal
     * @return the {@code NamePrincipal} or {@code null} if the principal cannot be converted
     */
    public static NamePrincipal from(Principal principal) {
        if (principal instanceof NamePrincipal) {
            return (NamePrincipal) principal;
        }
        return isConvertibleTo(principal) ? new NamePrincipal(principal.getName()) : null;
    }

    /**
     * Check if the given principal could be converted to a {@code NamePrincipal}.
     *
     * @param principal the original principal
     * @return {@code true} if the principal can be converted to a {@code NamePrincipal} and {@code false} otherwise
     */
    public static boolean isConvertibleTo(Principal principal) {
        if (principal instanceof NamePrincipal) {
            return true;
        }
        if (principal != null) {
            String name = principal.getName();
            if (name != null && ! name.isEmpty()) {
                return true;
            }
        }
        return false;
    }
}
