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
import org.wildfly.security.util._private.Arrays2;

/**
 * Tests of org.wildfly.security.util.Arrays2
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class Arrays2Test {

    @Test
    public void testEqualsBytesOffset1BytesOffset2Len() throws Exception {
        assertTrue(Arrays2.equals(new byte[]{'x','a','b','c','x'}, 1, new byte[]{'y','y','a','b','c','y'}, 2, 3));
        assertTrue(Arrays2.equals(new byte[]{'a','b','c'}, 0, new byte[]{'a','b','c'}, 0, 3));
        assertTrue(Arrays2.equals(new byte[]{}, 0, new byte[]{'a','b','c'}, 3, 0));
        assertFalse(Arrays2.equals(new byte[]{'a','x','c'}, 0, new byte[]{'a','y','c'}, 0, 3));
    }

    @Test
    public void testEqualsBytesOffset1Bytes() throws Exception {
        assertTrue(Arrays2.equals(new byte[]{'x','x','a','b','c','x'}, 2, new byte[]{'a','b','c'}));
        assertTrue(Arrays2.equals(new byte[]{'a','b','c'}, 0, new byte[]{'a','b','c'}));
    }

    @Test
    public void testEqualsCharsOffset1CharsOffset2Len() throws Exception {
        assertTrue(Arrays2.equals(new char[]{'x','a','b','c','x'}, 1, new char[]{'y','y','a','b','c','y'}, 2, 3));
        assertTrue(Arrays2.equals(new char[]{'a','b','c'}, 0, new char[]{'a','b','c'}, 0, 3));
        assertTrue(Arrays2.equals(new char[]{}, 0, new char[]{'a','b','c'}, 3, 0));
        assertFalse(Arrays2.equals(new char[]{'a','x','c'}, 0, new char[]{'a','y','c'}, 0, 3));
    }

    @Test
    public void testEqualsCharsOffset1Chars() throws Exception {
        assertTrue(Arrays2.equals(new char[]{'x','x','a','b','c','x'}, 2, new char[]{'a','b','c'}));
        assertTrue(Arrays2.equals(new char[]{'a','b','c'}, 0, new char[]{'a','b','c'}));
    }

    @Test
    public void testEqualsCharsOffset1StringOffset2Len() throws Exception {
        assertTrue(Arrays2.equals(new char[]{'x','a','b','c','x'}, 1, "yyabcy", 2, 3));
        assertTrue(Arrays2.equals(new char[]{'a','b','c'}, 0, "abc", 0, 3));
    }

    @Test
    public void testEqualsCharsOffset1String() throws Exception {
        assertTrue(Arrays2.equals(new char[]{'x','x','a','b','c','x'}, 2, "abc"));
        assertTrue(Arrays2.equals(new char[]{'a','b','c'}, 0, "abc"));
    }

    @Test
    public void testEqualsStringOffset1Chars() throws Exception {
        assertTrue(Arrays2.equals("xxabcx", 2, new char[]{'a','b','c'}));
        assertTrue(Arrays2.equals("abc", 0, new char[]{'a','b','c'}));
    }

}
