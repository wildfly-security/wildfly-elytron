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

package org.wildfly.security.util;

import static org.junit.Assert.*;

import java.util.NoSuchElementException;

import org.junit.Test;
import org.wildfly.common.array.Arrays2;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class ArrayIteratorTest {

    @Test
    public void testFwdAsc() {
        final ArrayIterator<String> iterator = new ArrayIterator<>(Arrays2.of("one", "two", "three"));
        assertTrue(iterator.hasNext());
        assertEquals("one", iterator.next());
        assertTrue(iterator.hasNext());
        assertEquals("two", iterator.next());
        assertTrue(iterator.hasNext());
        assertEquals("three", iterator.next());
        assertFalse(iterator.hasNext());
        try {
            iterator.next();
            fail("Expected NoSuchElementException");
        } catch (NoSuchElementException ignored){}
    }

    @Test
    public void testFwdDesc() {
        final ArrayIterator<String> iterator = new ArrayIterator<>(Arrays2.of("one", "two", "three"), true);
        assertTrue(iterator.hasNext());
        assertEquals("three", iterator.next());
        assertTrue(iterator.hasNext());
        assertEquals("two", iterator.next());
        assertTrue(iterator.hasNext());
        assertEquals("one", iterator.next());
        assertFalse(iterator.hasNext());
        try {
            iterator.next();
            fail("Expected NoSuchElementException");
        } catch (NoSuchElementException ignored){}
    }

    @Test
    public void testRevAsc() {
        final ArrayIterator<String> iterator = new ArrayIterator<>(Arrays2.of("one", "two", "three"), 3);
        assertTrue(iterator.hasPrevious());
        assertEquals("three", iterator.previous());
        assertTrue(iterator.hasPrevious());
        assertEquals("two", iterator.previous());
        assertTrue(iterator.hasPrevious());
        assertEquals("one", iterator.previous());
        assertFalse(iterator.hasPrevious());
        try {
            iterator.previous();
            fail("Expected NoSuchElementException");
        } catch (NoSuchElementException ignored){}
    }

    @Test
    public void testRevDesc() {
        final ArrayIterator<String> iterator = new ArrayIterator<>(Arrays2.of("one", "two", "three"), true, 0);
        assertTrue(iterator.hasPrevious());
        assertEquals("one", iterator.previous());
        assertTrue(iterator.hasPrevious());
        assertEquals("two", iterator.previous());
        assertTrue(iterator.hasPrevious());
        assertEquals("three", iterator.previous());
        assertFalse(iterator.hasPrevious());
        try {
            iterator.previous();
            fail("Expected NoSuchElementException");
        } catch (NoSuchElementException ignored){}
    }

    @Test
    public void testEmpty() {
        final ArrayIterator<String> iterator = new ArrayIterator<>(Arrays2.of());
        assertFalse(iterator.hasNext());
        assertFalse(iterator.hasPrevious());
    }

    @Test
    public void testIndex() {
        final ArrayIterator<String> iterator = new ArrayIterator<>(Arrays2.of("one", "two", "three"));
        assertTrue(iterator.hasNext());
        assertEquals("one", iterator.next());
        assertEquals(0, iterator.previousIndex());
        assertEquals(1, iterator.nextIndex());
        assertTrue(iterator.hasNext());
        assertEquals("two", iterator.next());
        assertEquals(1, iterator.previousIndex());
        assertEquals(2, iterator.nextIndex());
        assertTrue(iterator.hasNext());
        assertEquals("three", iterator.next());
        assertEquals(2, iterator.previousIndex());
        assertEquals(3, iterator.nextIndex());
        assertFalse(iterator.hasNext());
    }

    @Test
    public void testReversal() {
        final ArrayIterator<String> iterator = new ArrayIterator<>(Arrays2.of("one", "two", "three"));
        assertTrue(iterator.hasNext());
        assertEquals("one", iterator.next());
        assertTrue(iterator.hasNext());
        assertEquals("two", iterator.next());
        assertTrue(iterator.hasPrevious());
        assertEquals("two", iterator.previous());
        assertTrue(iterator.hasPrevious());
        assertEquals("one", iterator.previous());
        assertFalse(iterator.hasPrevious());
        assertTrue(iterator.hasNext());
        assertEquals("one", iterator.next());
        assertTrue(iterator.hasNext());
        assertEquals("two", iterator.next());
        assertTrue(iterator.hasNext());
        assertEquals("three", iterator.next());
        assertFalse(iterator.hasNext());
        assertTrue(iterator.hasPrevious());
        assertEquals("three", iterator.previous());
        assertTrue(iterator.hasNext());
    }
}
