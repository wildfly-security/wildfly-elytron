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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;

import org.wildfly.security.manager._private.SecurityMessages;

/**
 * A permission collection for {@link WildFlySecurityManagerPermission} instances.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class WildFlySecurityManagerPermissionCollection extends PermissionCollection {

    private static final long serialVersionUID = 1L;

    private transient AtomicInteger set = new AtomicInteger(0);

    private static final ObjectStreamField[] serialPersistentFields = new ObjectStreamField[] {
        new ObjectStreamField("p1", int.class),
    };

    public void add(final Permission permission) throws SecurityException, IllegalArgumentException {
        if (isReadOnly()) throw SecurityMessages.permission.readOnlyPermCollection();
        if (permission instanceof WildFlySecurityManagerPermission) {
            setBit(((WildFlySecurityManagerPermission) permission).getKind().ordinal());
        } else {
            throw SecurityMessages.permission.wrongPermType(WildFlySecurityManagerPermission.class, permission);
        }
    }

    private void setBit(final int bit) {
        final AtomicInteger set = this.set;
        final int value = 1 << bit;
        int oldVal;
        do {
            oldVal = set.get();
            if ((oldVal & value) != 0) {
                // already set
                return;
            }
        } while (! set.compareAndSet(oldVal, oldVal | value));
    }

    public boolean isSet(final int bit) {
        return (set.get() & (1 << bit)) != 0;
    }

    public boolean implies(final Permission permission) {
        return permission instanceof WildFlySecurityManagerPermission && isSet(((WildFlySecurityManagerPermission) permission).getKind().ordinal());
    }

    public Enumeration<Permission> elements() {
        final int value = set.get();
        if (value == 0) return Collections.emptyEnumeration();
        return new Enumeration<Permission>() {
            private int bits = value;

            public boolean hasMoreElements() {
                return bits != 0;
            }

            public Permission nextElement() {
                final int bit = Integer.lowestOneBit(bits);
                if (bit == 0) throw new NoSuchElementException();
                bits &= ~bit;
                return WildFlySecurityManagerPermission.values[Integer.numberOfTrailingZeros(bit)].getPermission();
            }
        };
    }

    public boolean equals(final Object obj) {
        return obj instanceof WildFlySecurityManagerPermissionCollection && set.get() == ((WildFlySecurityManagerPermissionCollection) obj).set.get();
    }

    @Override
    public int hashCode() {
        return set.get() * 3559;
    }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        final ObjectInputStream.GetField getField = ois.readFields();
        final int value = getField.get("p1", 0);
        (set = new AtomicInteger()).lazySet(value);
    }

    private void writeObject(ObjectOutputStream oos) throws IOException {
        final ObjectOutputStream.PutField putField = oos.putFields();
        putField.put("p1", set.get());
        oos.writeFields();
    }
}
