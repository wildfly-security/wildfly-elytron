/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
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
