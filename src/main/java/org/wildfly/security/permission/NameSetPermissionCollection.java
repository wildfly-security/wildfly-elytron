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

import org.wildfly.common.Assert;
import org.wildfly.security.util.StringEnumeration;

/**
 * A permission collection for permissions with a finite set of names, which is based on a simple bit set.
 * In this type of collection, each bit represents a unique permission of a given name.  This type is not suitable for
 * permissions with actions.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class NameSetPermissionCollection extends AbstractPermissionCollection {
    private static final long serialVersionUID = - 9191397492173027470L;
    private final StringEnumeration nameEnumeration;

    /**
     * Construct a new instance.  The name enumeration is pulled from the source permission object.
     *
     * @param sourcePermission the source permission object (must not be {@code null})
     * @return the permission collection
     */
    public static AbstractPermissionCollection newInstance(final AbstractNameSetOnlyPermission<?> sourcePermission) {
        return newInstance(sourcePermission, sourcePermission.getNameEnumeration());
    }

    /**
     * Construct a new instance.
     *
     * @param sourcePermission the source permission object (must not be {@code null})
     * @param nameEnumeration the name enumeration for this permission type (must not be {@code null})
     * @return the permission collection
     */
    public static AbstractPermissionCollection newInstance(final AbstractPermission<?> sourcePermission, final StringEnumeration nameEnumeration) {
        Assert.checkNotNullParam("sourcePermission", sourcePermission);
        Assert.checkNotNullParam("nameEnumeration", nameEnumeration);
        final int size = nameEnumeration.size();
        if (size <= 32) {
            return new IntNameSetPermissionCollection(sourcePermission, nameEnumeration);
        } else if (size <= 64) {
            return new LongNameSetPermissionCollection(sourcePermission, nameEnumeration);
        } else {
            // TODO: add GiantNameSetPermissionCollection which uses AtomicIntegerArray
            throw Assert.unsupported();
        }
    }

    NameSetPermissionCollection(final AbstractPermission<?> sourcePermission, final StringEnumeration nameEnumeration) {
        super(sourcePermission);
        this.nameEnumeration = nameEnumeration;
    }

    StringEnumeration getNameEnumeration() {
        return nameEnumeration;
    }
}
