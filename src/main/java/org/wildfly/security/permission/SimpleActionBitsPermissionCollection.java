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
import java.util.Enumeration;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicReference;

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.util.ArrayIterator;

/**
 * A trivially simple permission collection, suitable as a default for most permission types (though probably not as efficient
 * as a specialized type in many cases).
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SimpleActionBitsPermissionCollection extends AbstractPermissionCollection {

    private static final AbstractActionSetPermission<?>[] NO_PERMS = new AbstractActionSetPermission<?>[0];

    private final AtomicReference<AbstractActionSetPermission<?>[]> permissionsRef = new AtomicReference<>(NO_PERMS);

    /**
     * Construct a new instance.
     *
     * @param sourcePermission the source permission for this collection (must not be {@code null})
     */
    public SimpleActionBitsPermissionCollection(final AbstractActionSetPermission<?> sourcePermission) {
        super(sourcePermission);
    }

    public int size() {
        return permissionsRef.get().length;
    }

    @Override
    protected void doAdd(final AbstractPermission<?> permission) {
        if (permission instanceof AbstractActionSetPermission<?>) {
            doAdd((AbstractActionSetPermission<?>) permission);
        }
        throw ElytronMessages.log.invalidPermissionType(AbstractActionSetPermission.class, permission);
    }

    /**
     * Adds a permission.
     *
     * @param permission the non-{@code null} permission
     */
    protected void doAdd(final AbstractActionSetPermission<?> permission) {
        AbstractActionSetPermission<?>[] oldVal, readVal, newVal;
        int count;
        final AtomicReference<AbstractActionSetPermission<?>[]> permissionsRef = this.permissionsRef;
        do {
            readVal = permissionsRef.get();
            count = 0;
            do {
                oldVal = readVal;
                AbstractActionSetPermission<?> merged = permission;
                retry: for (;;) {
                    for (AbstractActionSetPermission<?> test : oldVal) {
                        if (test.implies(merged)) {
                            // fail fast
                            return;
                        }
                        if (test.nameEquals(merged)) {
                            // combine
                            merged = merged.withActionBits(permission.getActionBits());
                            // test again with merged permission
                            count = 0;
                            continue retry;
                        }
                        if (! merged.implies(test)) {
                            // prepare to skip any permissions that are obviated by this one
                            count ++;
                        }
                    }
                    break;
                }
                // see if it's still what we expect before we commit to the possibly expensive update...
                readVal = permissionsRef.get();
            } while (readVal != oldVal);
            newVal = new AbstractActionSetPermission<?>[count + 1];
            int i = 0;
            for (AbstractActionSetPermission<?> test : oldVal) {
                if (! permission.implies(test)) {
                    newVal[i++] = test;
                }
            }
            newVal[i] = permission;
        } while (! permissionsRef.compareAndSet(oldVal, newVal));
    }

    public boolean implies(final Permission permission) {
        for (Permission test : permissionsRef.get()) {
            if (test.implies(permission)) {
                return true;
            }
        }
        return false;
    }

    public Iterator<Permission> iterator() {
        return new ArrayIterator<Permission>(permissionsRef.get());
    }

    public Enumeration<Permission> elements() {
        return new ArrayIterator<Permission>(permissionsRef.get());
    }
}
