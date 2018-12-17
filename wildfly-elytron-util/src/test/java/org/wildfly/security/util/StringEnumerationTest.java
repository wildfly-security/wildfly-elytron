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

import org.junit.Test;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class StringEnumerationTest {
    @SuppressWarnings("RedundantStringConstructorCall")
    @Test
    public void testBasic() {
        // we use string ctor to do accurate identity checks
        final String foo = new String("foo");
        final String bar = new String("bar");
        final String baz = new String("baz");
        final String zap = new String("zap");
        StringEnumeration e = StringEnumeration.of(foo, bar, baz, zap);
        assertEquals("foo", e.nameOf(0));
        assertEquals("bar", e.nameOf(1));
        assertEquals("baz", e.nameOf(2));
        assertEquals("zap", e.nameOf(3));
        assertEquals(0, e.indexOf("foo"));
        assertEquals(1, e.indexOf("bar"));
        assertEquals(2, e.indexOf("baz"));
        assertEquals(3, e.indexOf("zap"));
        assertSame(foo, e.canonicalName("foo"));
        assertSame(bar, e.canonicalName("bar"));
        assertSame(baz, e.canonicalName("baz"));
        assertSame(zap, e.canonicalName("zap"));
        assertEquals(4, e.size());
    }
}
