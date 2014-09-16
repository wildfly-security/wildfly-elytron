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
 * Tests of org.wildfly.security.util.CharacterArrayReader
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class CharacterArrayReaderTest {

    @Test
    public void testEmpty() throws Exception {
        CharacterArrayReader r = new CharacterArrayReader(new char[]{});
        try{
            r.read();
            throw new Exception("Not throwed NoSuchElementException");
        } catch(NoSuchElementException e){
        } finally {
            r.close();
        }
    }

    @Test
    public void testBase() throws Exception {
        CharacterArrayReader r = new CharacterArrayReader(new char[]{'a','b'});

        assertEquals('a', r.read());
        assertEquals('b', r.read());

        try{
            r.read();
            throw new Exception("Not throwed NoSuchElementException");
        }
        catch(NoSuchElementException e){
        } finally {
            r.close();
        }
    }

    @Test
    public void testContructor0() throws Exception {
        CharacterArrayReader r = new CharacterArrayReader(new char[]{'a','b'},0);

        assertEquals('a', r.read());
        assertEquals('b', r.read());

        try{
            r.read();
            throw new Exception("Not throwed NoSuchElementException");
        }
        catch(NoSuchElementException e){
        } finally {
            r.close();
        }
    }

    @Test
    public void testConstructor1() throws Exception {
        CharacterArrayReader r = new CharacterArrayReader(new char[]{'a','b'},1);

        assertEquals('b', r.read());

        try{
            r.read();
            throw new Exception("Not throwed NoSuchElementException");
        }
        catch(NoSuchElementException e){
        } finally {
            r.close();
        }
    }

    @Test
    public void testConstructor2() throws Exception {
        try{
            new CharacterArrayReader(new char[]{'a','b'},3);
            throw new Exception("Not throwed IllegalArgumentException");
        }
        catch(IllegalArgumentException e){}
    }

    @Test
    public void testOutputInt() throws Exception {
        CharacterArrayReader r = new CharacterArrayReader(new char[]{'a','\u4F60',0x4321});
        assertEquals(0x000061, r.read());
        assertEquals(0x004F60, r.read());
        assertEquals(0x004321, r.read());
        r.close();
    }

    @Test
    public void testDistanceToAndSkip() throws Exception {
        CharacterArrayReader r = new CharacterArrayReader("abcdabcdabcd".toCharArray());
        assertEquals(0, r.distanceTo('a'));
        assertEquals(1, r.distanceTo('b'));
        assertEquals(2, r.distanceTo('c'));

        r.read();
        assertEquals(3, r.distanceTo('a'));
        assertEquals(0, r.distanceTo('b'));
        assertEquals(1, r.distanceTo('c'));

        r.skip(0);
        assertEquals(3, r.distanceTo('a'));
        assertEquals(0, r.distanceTo('b'));
        assertEquals(1, r.distanceTo('c'));

        r.skip(5);
        assertEquals(2, r.distanceTo('a'));
        assertEquals(3, r.distanceTo('b'));
        assertEquals(0, r.distanceTo('c'));
        r.close();
    }

    @Test
    public void testContentEqualsAndSkip() throws Exception {
        CharacterArrayReader r = new CharacterArrayReader("abcdefgh".toCharArray());
        assertTrue(r.contentEquals("abcd"));
        assertFalse(r.contentEquals("bcd"));
        assertFalse(r.contentEquals("defg"));

        assertEquals('a', r.read());
        assertTrue(r.contentEquals("bcd"));
        assertFalse(r.contentEquals("abcd"));
        assertFalse(r.contentEquals("defg"));

        r.skip(2);
        assertFalse(r.contentEquals("bcd"));
        assertFalse(r.contentEquals("abcd"));
        assertTrue(r.contentEquals("defg"));
        assertEquals('d', r.read());
        r.close();
    }

}
