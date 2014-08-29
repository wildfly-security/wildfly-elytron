/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import org.junit.Test;

import java.util.NoSuchElementException;

/**
 * Tests of org.wildfly.security.util.CharacterArrayIterator
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class CharacterArrayIteratorTest {

    @Test
    public void testEmpty() throws Exception {
        CharacterArrayIterator it = new CharacterArrayIterator(new char[]{});
        assertFalse(it.hasNext());
        try{
            it.next();
            throw new Exception("Not throwed NoSuchElementException");
        }
        catch(NoSuchElementException e){}
    }

    @Test
    public void testBase() throws Exception {
        CharacterArrayIterator it = new CharacterArrayIterator(new char[]{'a','b'});
        assertTrue(it.hasNext());

        assertEquals('a', it.next());
        assertTrue(it.hasNext());

        assertEquals('b', it.next());
        assertFalse(it.hasNext());

        try{
            it.next();
            throw new Exception("Not throwed NoSuchElementException");
        }
        catch(NoSuchElementException e){}
        assertFalse(it.hasNext());
    }

    @Test
    public void testContructor0() throws Exception {
        CharacterArrayIterator it = new CharacterArrayIterator(new char[]{'a','b'},0);
        assertTrue(it.hasNext());

        assertEquals('a', it.next());
        assertTrue(it.hasNext());

        assertEquals('b', it.next());
        assertFalse(it.hasNext());

        try{
            it.next();
            throw new Exception("Not throwed NoSuchElementException");
        }
        catch(NoSuchElementException e){}
        assertFalse(it.hasNext());
    }

    @Test
    public void testConstructor1() throws Exception {
        CharacterArrayIterator it = new CharacterArrayIterator(new char[]{'a','b'},1);
        assertTrue(it.hasNext());

        assertEquals('b', it.next());
        assertFalse(it.hasNext());

        try{
            it.next();
            throw new Exception("Not throwed NoSuchElementException");
        }
        catch(NoSuchElementException e){}
        assertFalse(it.hasNext());
    }

    @Test
    public void testConstructor2() throws Exception {
        try{
            new CharacterArrayIterator(new char[]{'a','b'},2);
            throw new Exception("Not throwed NoSuchElementException");
        }
        catch(NoSuchElementException e){}
    }

    @Test
    public void testOutputInt() throws Exception {
        CharacterArrayIterator it = new CharacterArrayIterator(new char[]{'a','\u4F60',0x4321});
        assertEquals(0x000061, it.next());
        assertEquals(0x004F60, it.next());
        assertEquals(0x004321, it.next());
    }

    @Test
    public void testDistanceToAndSkip() throws Exception {
        CharacterArrayIterator it = new CharacterArrayIterator("abcdabcdabcd".toCharArray());
        assertEquals(0, it.distanceTo('a'));
        assertEquals(1, it.distanceTo('b'));
        assertEquals(2, it.distanceTo('c'));

        it.next();
        assertEquals(3, it.distanceTo('a'));
        assertEquals(0, it.distanceTo('b'));
        assertEquals(1, it.distanceTo('c'));

        it.skip(0);
        assertEquals(3, it.distanceTo('a'));
        assertEquals(0, it.distanceTo('b'));
        assertEquals(1, it.distanceTo('c'));

        it.skip(5);
        assertEquals(2, it.distanceTo('a'));
        assertEquals(3, it.distanceTo('b'));
        assertEquals(0, it.distanceTo('c'));
    }

    @Test
    public void testContentEqualsAndSkip() throws Exception {
        CharacterArrayIterator it = new CharacterArrayIterator("abcdefgh".toCharArray());
        assertTrue(it.contentEquals("abcd"));
        assertFalse(it.contentEquals("bcd"));
        assertFalse(it.contentEquals("defg"));

        assertEquals('a', it.next());
        assertTrue(it.contentEquals("bcd"));
        assertFalse(it.contentEquals("abcd"));
        assertFalse(it.contentEquals("defg"));

        it.skip(2);
        assertFalse(it.contentEquals("bcd"));
        assertFalse(it.contentEquals("abcd"));
        assertTrue(it.contentEquals("defg"));
        assertEquals('d', it.next());
    }

}
