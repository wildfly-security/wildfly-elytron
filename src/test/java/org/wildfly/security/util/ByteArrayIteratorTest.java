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
 * Tests of org.wildfly.security.util.ByteArrayIterator
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class ByteArrayIteratorTest {

    @Test
    public void testEmpty() throws Exception {
        ByteArrayIterator it = new ByteArrayIterator(new byte[]{});
        assertFalse(it.hasNext());
        try{
            it.next();
            throw new Exception("Not throwed NoSuchElementException");
        }
        catch(NoSuchElementException e){}
    }

    @Test
    public void testBase() throws Exception {
        ByteArrayIterator it = new ByteArrayIterator(new byte[]{0x01,0x02});
        assertTrue(it.hasNext());

        assertEquals(0x01, it.next());
        assertTrue(it.hasNext());

        assertEquals(0x02, it.next());
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
        ByteArrayIterator it = new ByteArrayIterator(new byte[]{0x01,0x02});
        assertTrue(it.hasNext());

        assertEquals(0x01, it.next());
        assertTrue(it.hasNext());

        assertEquals(0x02, it.next());
        assertFalse(it.hasNext());

        try{
            it.next();
            throw new Exception("Not throwed NoSuchElementException");
        }
        catch(NoSuchElementException e){}
        assertFalse(it.hasNext());
    }

    @Test
    public void testContructor1() throws Exception {
        ByteArrayIterator it = new ByteArrayIterator(new byte[]{0x01,0x02},1);
        assertTrue(it.hasNext());

        assertEquals(0x02, it.next());
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
            new ByteArrayIterator(new byte[]{0x01,0x02},2);
            throw new Exception("Not throwed NoSuchElementException");
        }
        catch(NoSuchElementException e){}
    }

    @Test
    public void testOutputInt() throws Exception {
        ByteArrayIterator it = new ByteArrayIterator(new byte[]{0x12});
        assertEquals(0x000012, it.next());
    }

}
