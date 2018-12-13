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
import java.security.PermissionCollection;
import java.util.Enumeration;
import java.util.Iterator;

import org.wildfly.common.Assert;
import org.wildfly.security.permission.ElytronMessages;

/**
 * Base class for useful permission collections.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractPermissionCollection extends PermissionCollection implements Iterable<Permission>, PermissionVerifier {
    private static final long serialVersionUID = - 7532778883140764647L;

    private final AbstractPermission<?> sourcePermission;

    /**
     * Construct a new instance.
     *
     * @param sourcePermission the source permission for this collection (must not be {@code null})
     */
    protected AbstractPermissionCollection(final AbstractPermission<?> sourcePermission) {
        Assert.checkNotNullParam("sourcePermission", sourcePermission);
        this.sourcePermission = sourcePermission;
    }

    /**
     * Get the size of this permission collection.
     *
     * @return the size of this permission collection
     */
    public abstract int size();

    /**
     * Iterate over this permission collection.
     *
     * @return the iterator (not {@code null})
     */
    public abstract Iterator<Permission> iterator();

    /**
     * Iterate over this permission collection.
     *
     * @return the iterator (not {@code null})
     */
    public abstract Enumeration<Permission> elements();

    /**
     * Add an item to this collection.  The permission class must be the same as the source permission's class.
     *
     * @param permission the permission to add (must not be {@code null})
     */
    public final void add(final Permission permission) {
        Assert.checkNotNullParam("permission", permission);
        if (isReadOnly()) throw ElytronMessages.log.readOnlyPermissionCollection();
        @SuppressWarnings("rawtypes")
        Class<? extends AbstractPermission> expected = sourcePermission.getClass().asSubclass(AbstractPermission.class);
        if (expected != permission.getClass()) {
            throw ElytronMessages.log.invalidPermissionType(expected, permission);
        }
        doAdd(expected.cast(permission));
    }

    /**
     * Perform the work of adding a permission.  The permission is guaranteed to be of the correct type and the collection
     * is guaranteed to have been writable at the time the {@link #add(Permission)} method was called.
     *
     * @param permission the non-{@code null} permission
     */
    protected abstract void doAdd(final AbstractPermission<?> permission);

    final AbstractPermission<?> getSourcePermission() {
        return sourcePermission;
    }

    final Object writeReplace() {
        return new SerializedPermissionCollection(this);
    }
}
