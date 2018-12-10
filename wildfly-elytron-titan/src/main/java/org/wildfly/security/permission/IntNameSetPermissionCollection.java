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
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;

import org.wildfly.security.util.EnumerationIterator;
import org.wildfly.security.util.StringEnumeration;

final class IntNameSetPermissionCollection extends NameSetPermissionCollection {

    private final AtomicInteger bitSet = new AtomicInteger();

    IntNameSetPermissionCollection(final AbstractPermission<?> sourcePermission, final StringEnumeration nameEnumeration) {
        super(sourcePermission, nameEnumeration);
    }

    private Permission permissionFor(int id) {
        return ((AbstractNamedPermission<?>)getSourcePermission()).withName(getNameEnumeration().nameOf(id));
    }

    protected void doAdd(final AbstractPermission<?> permission) {
        int setBits= getBitsForName(permission);
        final AtomicInteger bitSet = this.bitSet;
        int oldVal;
        do {
            oldVal = bitSet.get();
            if ((oldVal & setBits) == setBits) {
                return;
            }
        } while (! bitSet.compareAndSet(oldVal, oldVal | setBits));
    }

    public boolean implies(final Permission permission) {
        if (permission.getClass() != getSourcePermission().getClass()) {
            return false;
        }
        long testBits = getBitsForName(permission);
        return (bitSet.get() & testBits) == testBits;
    }

    public int size() {
        final int size = Integer.bitCount(bitSet.get());
        return size == getNameEnumeration().size() ? 1 : size;
    }

    public EnumerationIterator<Permission> iterator() {
        return new Iter(bitSet.get());
    }

    public EnumerationIterator<Permission> elements() {
        return iterator();
    }

    private int getBitsForName(final Permission permission) {
        final int bits;
        final String name = permission.getName();
        final StringEnumeration nameEnumeration = getNameEnumeration();
        if ("*".equals(name)) {
            // add all names
            bits = (1 << nameEnumeration.size()) - 1;
        } else {
            bits = 1 << nameEnumeration.indexOf(name);
        }
        return bits;
    }

    private class Iter implements EnumerationIterator<Permission> {
        private int bits;

        Iter(final int bits) {
            this.bits = bits;
        }

        public boolean hasMoreElements() {
            return bits != 0;
        }

        public Permission nextElement() {
            final int bits = this.bits;
            if (bits == 0) throw new NoSuchElementException();
            if (Integer.bitCount(bits) == getNameEnumeration().size()) {
                this.bits = 0;
                return ((AbstractNamedPermission<?>) getSourcePermission()).withName("*");
            }
            int bit = Integer.lowestOneBit(bits);
            this.bits = bits & ~bit;
            return permissionFor(Integer.numberOfTrailingZeros(bit));
        }

        public boolean hasNext() {
            return hasMoreElements();
        }

        public Permission next() {
            return nextElement();
        }
    }

}
