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

import static org.junit.Assert.*;

import java.security.Permission;
import java.util.Iterator;

import org.junit.Test;

public class TestAbstractNameOnlyPermission {
    @Test
    public void testBasic() {
        assertTrue(new SomePermission("name").implies(new SomePermission("name")));
        assertTrue(new SomePermission("name").implies(new SomePermission("otherName").withName("name")));
        assertFalse(new SomePermission("name").implies(new SomePermission("otherName")));
        assertFalse(new SomePermission("name").implies(new SomeOtherPermission("name")));
        assertFalse(new SomePermission("name").implies(NoPermission.getInstance()));
        assertTrue(new SomePermission("*").implies(new SomePermission("name")));
        assertTrue(new SomePermission("*").implies(new SomePermission("*")));
        assertFalse(new SomePermission("name").implies(new SomePermission("*")));
        assertFalse(new SomePermission("*").implies(new SomeOtherPermission("name")));
        assertFalse(new SomePermission("*").implies(new SomeOtherPermission("*")));
        assertFalse(new SomePermission("*").implies(NoPermission.getInstance()));
        assertEquals(new SomePermission("name"), new SomePermission("name"));
        assertNotEquals(new SomePermission("name"), new SomePermission("otherName"));
        assertEquals(new SomePermission("name"), new SomePermission("otherName").withName("name"));
    }

    @Test
    public void testCollection() {
        final AbstractPermissionCollection collection = new SomePermission("xx").newPermissionCollection();
        assertEquals(0, collection.size());
        Iterator<Permission> iterator = collection.iterator();
        assertFalse(iterator.hasNext());
        collection.add(new SomePermission("name1"));
        collection.add(new SomePermission("name2"));
        assertEquals(2, collection.size());
        iterator = collection.iterator();
        assertTrue(iterator.hasNext());
        assertNotNull(iterator.next());
        assertTrue(iterator.hasNext());
        assertNotNull(iterator.next());
        assertFalse(iterator.hasNext());
        assertTrue(collection.implies(new SomePermission("name1")));
        assertTrue(collection.implies(new SomePermission("name2")));
        assertFalse(collection.implies(new SomePermission("name3")));
        assertFalse(collection.implies(new SomePermission("*")));
        assertFalse(collection.implies(new SomeOtherPermission("name1")));
        assertFalse(collection.implies(new SomeOtherPermission("name3")));
        assertFalse(collection.implies(new SomeOtherPermission("*")));
        collection.add(new SomePermission("*"));
        assertEquals(1, collection.size());
        assertTrue(collection.implies(new SomePermission("name1")));
        assertTrue(collection.implies(new SomePermission("name2")));
        assertTrue(collection.implies(new SomePermission("name3")));
        assertTrue(collection.implies(new SomePermission("*")));
        assertFalse(collection.implies(new SomeOtherPermission("name1")));
        assertFalse(collection.implies(new SomeOtherPermission("name3")));
        assertFalse(collection.implies(new SomeOtherPermission("*")));
        iterator = collection.iterator();
        assertTrue(iterator.hasNext());
        assertEquals(new SomePermission("*"), iterator.next());
        assertFalse(iterator.hasNext());
    }

    @Test
    public void testSerialization() {
        SomePermission perm = new SomePermission("name");
        SerializedPermission obj = (SerializedPermission) perm.writeReplace();
        SomePermission resolved = (SomePermission) obj.readResolve();
        assertEquals(perm, resolved);

        AbstractPermissionCollection permissions = perm.newPermissionCollection();
        permissions.add(new SomePermission("otherName"));
        SerializedPermissionCollection obj2 = (SerializedPermissionCollection) permissions.writeReplace();
        AbstractPermissionCollection resolvedCollection = (AbstractPermissionCollection) obj2.readResolve();
        assertTrue(PermissionUtil.equals(permissions, resolvedCollection));
        Iterator<Permission> iterator = resolvedCollection.iterator();
        assertTrue(iterator.hasNext());
        assertEquals(new SomePermission("otherName"), iterator.next());
        assertFalse(iterator.hasNext());
    }

    public static final class SomePermission extends AbstractNameOnlyPermission<SomePermission> {
        public SomePermission(final String name) {
            super(name);
        }

        public SomePermission withName(final String name) {
            return new SomePermission(name);
        }
    }

    public static final class SomeOtherPermission extends AbstractNameOnlyPermission<SomeOtherPermission> {
        public SomeOtherPermission(final String name) {
            super(name);
        }

        public SomeOtherPermission withName(final String name) {
            return new SomeOtherPermission(name);
        }
    }
}
