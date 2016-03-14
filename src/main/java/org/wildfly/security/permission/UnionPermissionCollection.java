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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Enumeration;

import org.wildfly.security._private.ElytronMessages;

final class UnionPermissionCollection extends PermissionCollection {
    private static final long serialVersionUID = 6731525842957764833L;

    private final PermissionCollection pc1;
    private final PermissionCollection pc2;

    UnionPermissionCollection(final PermissionCollection pc1, final PermissionCollection pc2) {
        this.pc1 = pc1;
        this.pc2 = pc2;
        setReadOnly();
    }

    public void add(final Permission permission) {
        throw ElytronMessages.log.readOnlyPermissionCollection();
    }

    public boolean implies(final Permission permission) {
        return pc1.implies(permission) || pc2.implies(permission);
    }

    public Enumeration<Permission> elements() {
        final Enumeration<Permission> e1 = pc1.elements();
        final Enumeration<Permission> e2 = pc2.elements();
        return new Enumeration<Permission>() {
            public boolean hasMoreElements() {
                return e1.hasMoreElements() || e2.hasMoreElements();
            }

            public Permission nextElement() {
                return e1.hasMoreElements() ? e1.nextElement() : e2.nextElement();
            }
        };
    }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        if (pc1 == null) {
            throw ElytronMessages.log.invalidObjectNull("pc1");
        }
        if (pc2 == null) {
            throw ElytronMessages.log.invalidObjectNull("pc2");
        }
    }
}
