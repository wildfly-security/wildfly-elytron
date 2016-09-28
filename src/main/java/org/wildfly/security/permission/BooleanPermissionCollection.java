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
import java.util.Set;

/**
 * A permission collection type which either does or does not hold its instance.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class BooleanPermissionCollection extends AbstractPermissionCollection {
    private volatile boolean added;

    /**
     * Construct a new instance.
     *
     * @param sourcePermission the source permission for this collection (must not be {@code null})
     */
    public BooleanPermissionCollection(final AbstractPermission<?> sourcePermission) {
        super(sourcePermission);
    }

    public int size() {
        return added ? 1 : 0;
    }

    public Iterator<Permission> iterator() {
        return added ? getSingletonCollection().iterator() : Collections.emptyIterator();
    }

    public Enumeration<Permission> elements() {
        return added ? Collections.enumeration(getSingletonCollection()) : Collections.emptyEnumeration();
    }

    private Set<Permission> getSingletonCollection() {
        return Collections.singleton(getSourcePermission());
    }

    protected void doAdd(final AbstractPermission<?> permission) {
        added = true;
    }

    public boolean implies(final Permission permission) {
        return added && permission.getClass() == getSourcePermission().getClass();
    }
}
