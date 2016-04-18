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

/**
 * An abstract base class for named permissions with useful API and implementation methods.
 * <p>
 * Subclasses of this class are always serialized as a special serialized permission object, which captures the type class,
 * the permission name (if any), and the permission action (if any) as a string.  Therefore, none of the fields of any
 * subclass of this class are serialized unless they are included in the name or actions properties.
 * <p>
 * Concrete subclasses are expected to be immutable and final.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractNamedPermission<This extends AbstractNamedPermission<This>> extends AbstractPermission<This> {
    private static final long serialVersionUID = 5774685776540853292L;

    /**
     * Construct a new instance.
     *
     * @param name the permission name
     */
    protected AbstractNamedPermission(final String name) {
        super(name);
    }

    /**
     * Create a new permission which is identical to this one, except with a new {@code name}.
     *
     * @param name the name to use
     * @return the new permission (must not be {@code null})
     */
    public abstract This withName(String name);

    /**
     * Determine whether this permission has a name equal to the given name.
     *
     * @param name the name to check
     * @return {@code true} if this permission's name is equal to the given name, {@code false} otherwise
     */
    public boolean nameEquals(final String name) {
        return getName().equals(name);
    }

    /**
     * Determine whether this permission has a name equal to the name of the given permission.  If the given permission
     * is of a different type than this permission, {@code false} is returned.
     *
     * @param permission the permission whose name is to be checked
     * @return {@code true} if this permission's name is equal to the given permission's name, {@code false} otherwise
     */
    @SuppressWarnings("unchecked")
    public final boolean nameEquals(final Permission permission) {
        return permission != null && permission.getClass() == getClass() && nameEquals((This) permission);
    }

    /**
     * Determine whether this permission has a name equal to the name of the given permission.
     *
     * @param permission the permission whose name is to be checked
     * @return {@code true} if this permission's name is equal to the given permission's name, {@code false} otherwise
     */
    public final boolean nameEquals(final This permission) {
        return permission != null && nameEquals(permission.getName());
    }

    /**
     * Get the hash code of the name.  The default implementation returns {@code getName().hashCode()}.
     *
     * @return the hash code of the name
     */
    protected int nameHashCode() {
        return getName().hashCode();
    }

    /**
     * Determine whether this permission implies the given name.
     *
     * @param name the name to check
     * @return {@code true} if this permission's name implies the given name, {@code false} otherwise
     */
    public boolean impliesName(final String name) {
        return nameEquals("*") || nameEquals(name);
    }

    /**
     * Determine whether this permission implies the name of the given permission.  If
     * the permission is not of the same type as this permission, {@code false} is returned.
     *
     * @param permission the permission whose name is to be checked
     * @return {@code true} if this permission's name implies the given name, {@code false} otherwise
     */
    @SuppressWarnings("unchecked")
    public final boolean impliesName(final Permission permission) {
        return permission != null && permission.getClass() == getClass() && impliesName((This) permission);
    }

    /**
     * Determine whether this permission implies the name of the given permission.
     *
     * @param permission the permission whose name is to be checked
     * @return {@code true} if this permission's name implies the given name, {@code false} otherwise
     */
    public boolean impliesName(final This permission) {
        return permission != null && impliesName(permission.getName());
    }

    public boolean implies(final This permission) {
        return permission != null && impliesName(permission);
    }

    public boolean equals(final This other) {
        return other != null && nameEquals(other);
    }

    public int hashCode() {
        return getClass().hashCode() * 71 + nameHashCode();
    }
}
