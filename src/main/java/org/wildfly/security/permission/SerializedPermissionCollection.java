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

import java.io.Serializable;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.ArrayList;

final class SerializedPermissionCollection implements Serializable {
    private static final long serialVersionUID = - 8745428905589938281L;

    private final Permission s;
    private final Permission[] p;
    private final boolean r;

    SerializedPermissionCollection(final AbstractPermissionCollection collection) {
        s = collection.getSourcePermission();
        final ArrayList<Permission> list = new ArrayList<>(collection.size());
        collection.forEach(list::add);
        p = list.toArray(PermissionUtil.NO_PERMISSIONS);
        r = collection.isReadOnly();
    }

    Object readResolve() {
        final PermissionCollection collection = s.newPermissionCollection();
        for (Permission permission : p) {
            collection.add(permission);
        }
        if (r) collection.setReadOnly();
        return collection;
    }
}
