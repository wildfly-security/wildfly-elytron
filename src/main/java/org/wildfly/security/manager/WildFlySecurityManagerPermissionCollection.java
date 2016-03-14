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

package org.wildfly.security.manager;

import java.io.Serializable;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Enumeration;

import org.wildfly.common.Assert;
import org.wildfly.security.permission.AbstractPermissionCollection;
import org.wildfly.security.util.StringMapping;

/**
 * Stub class for the unlikely event that a serialized instance is lying around somewhere.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@Deprecated
final class WildFlySecurityManagerPermissionCollection extends PermissionCollection implements Serializable {

    private static final long serialVersionUID = 1L;

    private final int p1;

    WildFlySecurityManagerPermissionCollection(final int p1) {
        this.p1 = p1;
    }

    public void add(final Permission permission) {
        throw Assert.unsupported();
    }

    public boolean implies(final Permission permission) {
        throw Assert.unsupported();
    }

    public Enumeration<Permission> elements() {
        throw Assert.unsupported();
    }

    Object readResolve() {
        final AbstractPermissionCollection collection = new WildFlySecurityManagerPermission("*").newPermissionCollection();
        final StringMapping<WildFlySecurityManagerPermission> mapping = WildFlySecurityManagerPermission.mapping;
        int bits = p1;
        while (bits != 0) {
            collection.add(mapping.getItemById(Integer.numberOfTrailingZeros(Integer.lowestOneBit(bits))));
        }
        if (isReadOnly()) {
            collection.setReadOnly();
        }
        return collection;
    }
}
