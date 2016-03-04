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

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;

final class IntersectionPermissionCollection extends PermissionCollection {
    private static final long serialVersionUID = 8045087406778847303L;

    private final PermissionCollection pc1;
    private final PermissionCollection pc2;

    IntersectionPermissionCollection(final PermissionCollection pc1, final PermissionCollection pc2) {
        this.pc1 = pc1;
        this.pc2 = pc2;
        setReadOnly();
    }

    public void add(final Permission permission) {
        throw ElytronMessages.log.readOnlyPermissionCollection();
    }

    public boolean implies(final Permission permission) {
        return pc1.implies(permission) && pc2.implies(permission);
    }

    public Enumeration<Permission> elements() {
        // TODO: this is theoretically possible to implement using an IntersectionCollectionPermission;
        // however the primary use case is going to be in protection domains and verification scenarios so we may
        // not ever actually need this
        throw Assert.unsupported();
    }
}
