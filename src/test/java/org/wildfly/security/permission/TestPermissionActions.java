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
import static org.wildfly.security.permission.PermissionActions.getCanonicalActionString;

import java.util.EnumSet;

import org.junit.Test;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@SuppressWarnings("SpellCheckingInspection")
public class TestPermissionActions {
    enum ActionSetOne {
        foo,
        bar,
        baz
    }

    enum ActionSetTwo {
        foobar,
        foobaz,
        foobazz,
        foobarz,
        foobazr,
        fooba
    }

    @Test
    public void testCanonicalActionString() {
        assertEquals("foo,bar,baz", getCanonicalActionString(EnumSet.allOf(ActionSetOne.class)));
        assertEquals("", getCanonicalActionString(EnumSet.noneOf(ActionSetOne.class)));
        assertEquals("foo", getCanonicalActionString(EnumSet.of(ActionSetOne.foo)));
        assertEquals("foo,baz", getCanonicalActionString(EnumSet.of(ActionSetOne.foo, ActionSetOne.baz)));
    }

    @Test
    public void testParseValidActionString() {
        EnumSet<ActionSetOne> set;
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetOne.class, "");
        assertEquals(0, set.size());
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetOne.class, "bar,foo");
        assertEquals(2, set.size());
        assertTrue(set.contains(ActionSetOne.bar));
        assertTrue(set.contains(ActionSetOne.foo));
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetOne.class, "bar,foo,bar,bar");
        assertEquals(2, set.size());
        assertTrue(set.contains(ActionSetOne.bar));
        assertTrue(set.contains(ActionSetOne.foo));
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetOne.class, ",,bar,foo,,");
        assertEquals(2, set.size());
        assertTrue(set.contains(ActionSetOne.bar));
        assertTrue(set.contains(ActionSetOne.foo));
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetOne.class, "bar,foo,baz");
        assertEquals(3, set.size());
        assertTrue(set.contains(ActionSetOne.bar));
        assertTrue(set.contains(ActionSetOne.baz));
        assertTrue(set.contains(ActionSetOne.foo));
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetOne.class, "bar, foo ,baz");
        assertEquals(3, set.size());
        assertTrue(set.contains(ActionSetOne.bar));
        assertTrue(set.contains(ActionSetOne.baz));
        assertTrue(set.contains(ActionSetOne.foo));
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetOne.class, "    bar, foo ,baz          ");
        assertEquals(3, set.size());
        assertTrue(set.contains(ActionSetOne.bar));
        assertTrue(set.contains(ActionSetOne.baz));
        assertTrue(set.contains(ActionSetOne.foo));
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetOne.class, "*");
        assertEquals(3, set.size());
        assertTrue(set.contains(ActionSetOne.bar));
        assertTrue(set.contains(ActionSetOne.baz));
        assertTrue(set.contains(ActionSetOne.foo));
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetOne.class, "*,bar");
        assertEquals(3, set.size());
        assertTrue(set.contains(ActionSetOne.bar));
        assertTrue(set.contains(ActionSetOne.baz));
        assertTrue(set.contains(ActionSetOne.foo));
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetOne.class, ",bar,*,bar");
        assertEquals(3, set.size());
        assertTrue(set.contains(ActionSetOne.bar));
        assertTrue(set.contains(ActionSetOne.baz));
        assertTrue(set.contains(ActionSetOne.foo));
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetOne.class, "*,,,,,,baz");
        assertEquals(3, set.size());
        assertTrue(set.contains(ActionSetOne.bar));
        assertTrue(set.contains(ActionSetOne.baz));
        assertTrue(set.contains(ActionSetOne.foo));
    }

    @Test
    public void testParseInvalidActionString() {
        // ---
        try {
            PermissionActions.parseActionStringToSet(ActionSetOne.class, "xxx");
        } catch (IllegalArgumentException ignored) {}
        // ---
        try {
            PermissionActions.parseActionStringToSet(ActionSetOne.class, "barf,foo");
        } catch (IllegalArgumentException ignored) {}
        // ---
        try {
            PermissionActions.parseActionStringToSet(ActionSetOne.class, ",barf,foo,foo,");
        } catch (IllegalArgumentException ignored) {}
        // ---
        try {
            PermissionActions.parseActionStringToSet(ActionSetOne.class, "*,barf,foo");
        } catch (IllegalArgumentException ignored) {}
        // ---
        try {
            PermissionActions.parseActionStringToSet(ActionSetOne.class, "*,bar f,foo");
        } catch (IllegalArgumentException ignored) {}
        // ---
        try {
            PermissionActions.parseActionStringToSet(ActionSetOne.class, "*,bar foo,foo");
        } catch (IllegalArgumentException ignored) {}
        // ---
        try {
            PermissionActions.parseActionStringToSet(ActionSetOne.class, "FOO,BAR");
        } catch (IllegalArgumentException ignored) {}
        // ---
    }

    @Test
    public void testCommonPrefixActionString() {
        EnumSet<ActionSetTwo> set;
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetTwo.class, "");
        assertEquals(0, set.size());
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetTwo.class, "foobar,fooba");
        assertEquals(2, set.size());
        assertTrue(set.contains(ActionSetTwo.fooba));
        assertTrue(set.contains(ActionSetTwo.foobar));
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetTwo.class, "foobar,fooba,foobazz");
        assertEquals(3, set.size());
        assertTrue(set.contains(ActionSetTwo.fooba));
        assertTrue(set.contains(ActionSetTwo.foobar));
        assertTrue(set.contains(ActionSetTwo.foobazz));
        // ---
        set = PermissionActions.parseActionStringToSet(ActionSetTwo.class, "foobar,fooba,foobazz,foobaz");
        assertEquals(4, set.size());
        assertTrue(set.contains(ActionSetTwo.fooba));
        assertTrue(set.contains(ActionSetTwo.foobar));
        assertTrue(set.contains(ActionSetTwo.foobaz));
        assertTrue(set.contains(ActionSetTwo.foobazz));
    }
}
