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

import org.wildfly.security._private.ElytronMessages;

/**
 * An abstract base class for any permission.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractPermission<This extends AbstractPermission<This>> extends Permission implements PermissionVerifier {
    /**
     * Construct a new instance.
     *
     * @param name the permission name
     */
    protected AbstractPermission(final String name) {
        super(name);
    }

    /**
     * Determine whether this permission implies another permission.
     *
     * @param permission the other permission
     * @return {@code true} if this permission implies the other; {@code false} otherwise
     */
    @SuppressWarnings("unchecked")
    public final boolean implies(Permission permission) {
        return permission != null && getClass() == permission.getClass() && implies((This) permission);
    }

    /**
     * Determine whether this permission implies another permission.
     *
     * @param permission the other permission
     * @return {@code true} if this permission implies the other; {@code false} otherwise
     */
    public abstract boolean implies(This permission);

    /**
     * Determine whether this permission object is equal to another object.
     *
     * @param obj the object to compare to
     * @return {@code true} if the object is a permission equal to this one; {@code false} otherwise
     */
    @SuppressWarnings("unchecked")
    public final boolean equals(final Object obj) {
        return obj != null && obj.getClass() == getClass() && equals((This) obj);
    }

    /**
     * Determine whether this permission object is equal to another object of this permission type.
     *
     * @param other the permission to compare to
     * @return {@code true} if the object is a permission equal to this one; {@code false} otherwise
     */
    public abstract boolean equals(This other);

    /**
     * Get the hash code of this permission.  The result must be consistent with the defined {@link #equals(AbstractPermission)}
     * result.
     *
     * @return the hash code of this permission
     */
    public abstract int hashCode();

    /**
     * Get the actions string.  The default implementation always returns an empty string.
     *
     * @return the actions string (not {@code null})
     */
    public String getActions() {
        return "";
    }

    /**
     * Get an empty permission collection which is capable of holding instances of this permission type.
     * <p>
     * The default implementation returns a {@link SimplePermissionCollection}.
     *
     * @return the permission collection to use
     */
    public AbstractPermissionCollection newPermissionCollection() {
        return new SimplePermissionCollection(this);
    }

    /**
     * Check to ensure that the given action string is empty or {@code null}; otherwise, throw an exception.
     *
     * @param actions the actions string
     * @throws IllegalArgumentException if the actions string is not empty
     */
    protected static void requireEmptyActions(final String actions) throws IllegalArgumentException {
        if (actions != null && ! actions.isEmpty()) {
            throw ElytronMessages.log.expectedEmptyActions(actions);
        }
    }

    final Object writeReplace() {
        return new SerializedPermission(getClass(), getName(), getActions());
    }
}
