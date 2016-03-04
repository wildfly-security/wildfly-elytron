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
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A permission collection for actionless permissions which are organized by name.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ByNamePermissionCollection extends AbstractPermissionCollection {
    private final ConcurrentHashMap<String, Permission> byName = new ConcurrentHashMap<>();
    private volatile Permission all;

    /**
     * The source permission used to construct this collection.
     *
     * @param sourcePermission the source permission (must not be {@code null})
     */
    public ByNamePermissionCollection(final AbstractPermission<?> sourcePermission) {
        super(sourcePermission);
    }

    public int size() {
        return all != null ? 1 : byName.size();
    }

    public Iterator<Permission> iterator() {
        return all != null ? Collections.singleton(all).iterator() : Arrays.asList(byName.values().toArray(PermissionUtil.NO_PERMISSIONS)).iterator();
    }

    public Enumeration<Permission> elements() {
        return Collections.enumeration(all != null ? Collections.singleton(all) : Arrays.asList(byName.values().toArray(PermissionUtil.NO_PERMISSIONS)));
    }

    protected void doAdd(final AbstractPermission<?> permission) {
        if (permission.getName().equals("*")) {
            all = permission;
            byName.clear();
        } else {
            byName.putIfAbsent(permission.getName(), permission);
        }
    }

    public boolean implies(final Permission permission) {
        if (permission == null || getSourcePermission().getClass() != permission.getClass()) {
            return false;
        }
        final Permission all = this.all;
        if (all != null) {
            return all.implies(permission);
        }
        final Permission ourPermission = byName.get(permission.getName());
        return ourPermission != null && ourPermission.implies(permission);
    }
}
