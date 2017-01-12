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

package org.wildfly.security.auth.principal;

import java.io.Serializable;
import java.security.Principal;

/**
 * A principal which is represented by a numeric ID, such as what a database might use for a primary key.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class NumericPrincipal implements Principal, Serializable {
    private static final long serialVersionUID = 6679865697029801196L;

    /**
     * @serial the principal ID
     */
    private final long id;

    /**
     * Construct a new instance.
     *
     * @param id the ID of the principal
     */
    public NumericPrincipal(final long id) {
        this.id = id;
    }

    /**
     * Construct a new instance from a decimal string.
     *
     * @param id the ID of the principal, as a string
     * @throws NumberFormatException if the number is not a valid non-negative long integer
     */
    public NumericPrincipal(final String id) throws NumberFormatException {
        this(Long.parseUnsignedLong(id));
    }

    /**
     * Get the ID of the principal.
     *
     * @return the ID of the principal
     */
    public long getId() {
        return id;
    }

    /**
     * Determine whether this principal is equal to the given object.
     *
     * @param obj the object
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public boolean equals(final Object obj) {
        return obj instanceof NumericPrincipal && equals((NumericPrincipal) obj);
    }

    /**
     * Determine whether this principal is equal to the given object.
     *
     * @param obj the object
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public boolean equals(final NumericPrincipal obj) {
        return obj != null && id == obj.id;
    }

    /**
     * Get the hash code of this principal.
     *
     * @return the hash code of this principal
     */
    public int hashCode() {
        return (int) id;
    }

    /**
     * Get this principal as a string.
     *
     * @return this principal as a string (not {@code null})
     */
    public String toString() {
        return getName();
    }

    /**
     * Returns the name of this principal, which is just the string representation of the ID.
     *
     * @return the name of this principal (not {@code null})
     */
    public String getName() {
        return Long.toUnsignedString(id);
    }
}
