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
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;

/**
 * The permission collection type for {@link NoPermission}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class NoPermissionCollection extends AbstractPermissionCollection {
    private static final long serialVersionUID = - 8826282614161412469L;

    private static NoPermissionCollection INSTANCE = new NoPermissionCollection();

    NoPermissionCollection() {
        super(NoPermission.getInstance());
    }

    static NoPermissionCollection getInstance() {
        return INSTANCE;
    }

    protected void doAdd(final AbstractPermission<?> permission) {
        // no action
    }

    public boolean implies(final Permission permission) {
        return false;
    }

    public Enumeration<Permission> elements() {
        return Collections.emptyEnumeration();
    }

    public Iterator<Permission> iterator() {
        return Collections.emptyIterator();
    }

    public int size() {
        return 0;
    }

    Object readResolve() {
        return INSTANCE;
    }

    public boolean equals(final Object obj) {
        return obj instanceof NoPermissionCollection;
    }

    public int hashCode() {
        return getClass().hashCode();
    }
}
