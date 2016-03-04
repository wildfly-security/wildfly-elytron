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
import java.util.NoSuchElementException;

import org.junit.Test;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class TestAbstractBooleanPermission {
    @Test
    public void testImplies() {
        assertTrue(new SomePermission().implies(new SomePermission()));
        assertFalse(new SomePermission().implies(NoPermission.getInstance()));
        assertFalse(new SomePermission().implies(new SomeOtherPermission()));
    }

    @Test
    public void testCollection() {
        final AbstractPermissionCollection collection = new SomePermission().newPermissionCollection();
        assertEquals(0, collection.size());
        collection.add(new SomePermission());
        assertEquals(1, collection.size());
        collection.add(new SomePermission());
        assertEquals(1, collection.size());
        final Iterator<Permission> iterator = collection.iterator();
        assertTrue(iterator.hasNext());
        assertEquals(new SomePermission(), iterator.next());
        assertFalse(iterator.hasNext());
        try {
            iterator.next();
            fail("Expected exception");
        } catch (NoSuchElementException ignored) {}
        try {
            collection.add(new SomeOtherPermission());
            fail("Expected exception");
        } catch (IllegalArgumentException ignored) {}
    }

    static final class SomePermission extends AbstractBooleanPermission<SomePermission> {
        SomePermission() {
        }
    }

    static final class SomeOtherPermission extends AbstractBooleanPermission<SomeOtherPermission> {
        SomeOtherPermission() {
        }
    }
}
