/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.security.manager;

import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;
import static org.wildfly.security.permission.PermissionActions.getCanonicalActionString;

import java.util.EnumSet;

import org.junit.Test;
import org.wildfly.security.permission.PermissionActions;

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
