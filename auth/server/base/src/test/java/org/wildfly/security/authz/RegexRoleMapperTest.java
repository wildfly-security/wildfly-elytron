/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.authz;

import org.junit.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RegexRoleMapperTest {

    @Test
    public void testRegexMapper() {
        Roles roles = createRoles("123-user", "joe", "abc-admin");
        RegexRoleMapper roleMapper = new RegexRoleMapper.Builder().setPattern(".*-([a-z]*)").setReplacement("$1").setKeepNonMapped(true).build();
        Roles mappedRoles = roleMapper.mapRoles(roles);

        assertTrue(mappedRoles.contains("user"));
        assertTrue(mappedRoles.contains("admin"));
        assertFalse(mappedRoles.contains("abc-admin"));
        assertFalse(mappedRoles.contains("123-user"));
        assertTrue(mappedRoles.contains("joe"));

        Iterator<String> iterator = mappedRoles.iterator();
        int count = 0;
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        assertEquals(count, 3);
    }

    @Test
    public void testRegexMapperDoNotKeepNonMapped() {
        Roles roles = createRoles("123-user", "joe", "abc-admin");
        RegexRoleMapper roleMapper = new RegexRoleMapper.Builder().setPattern(".*-([a-z]*)").setReplacement("$1").setKeepNonMapped(false).build();
        Roles mappedRoles = roleMapper.mapRoles(roles);

        assertTrue(mappedRoles.contains("user"));
        assertTrue(mappedRoles.contains("admin"));
        assertFalse(mappedRoles.contains("abc-admin"));
        assertFalse(mappedRoles.contains("123-user"));
        assertFalse(mappedRoles.contains("joe"));

        Iterator<String> iterator = mappedRoles.iterator();
        int count = 0;
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        assertEquals(count, 2);
    }

    @Test
    public void testRegexMapper2() {
        Roles roles = createRoles("APP-123_XY_ZX_ABCD-Batch_Admin", "joe", "APP-ABC_EF_GH_IJKL-Batch_Operator");
        RegexRoleMapper roleMapper = new RegexRoleMapper.Builder().setPattern(".*_([a-zA-Z]*)$").setReplacement("$1").setKeepNonMapped(false).build();
        Roles mappedRoles = roleMapper.mapRoles(roles);

        assertTrue(mappedRoles.contains("Admin"));
        assertTrue(mappedRoles.contains("Operator"));
        assertFalse(mappedRoles.contains("APP-123_XY_ZX_ABCD-Batch_Admin"));
        assertFalse(mappedRoles.contains("APP-ABC_EF_GH_IJKL-Batch_Operator"));
        assertFalse(mappedRoles.contains("joe"));

        Iterator<String> iterator = mappedRoles.iterator();
        int count = 0;
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        assertEquals(count, 2);
    }

    @Test
    public void testRegexMapper3() {
        Roles roles = createRoles("USER_ABC_DEF", "joe", "ADMIN_123");
        RegexRoleMapper roleMapper = new RegexRoleMapper.Builder().setPattern("^([a-zA-Z]*)_.*").setReplacement("APP-$1").setKeepNonMapped(true).build();
        Roles mappedRoles = roleMapper.mapRoles(roles);

        assertFalse(mappedRoles.contains("USER_ABC_DEF"));
        assertFalse(mappedRoles.contains("ADMIN_123"));
        assertTrue(mappedRoles.contains("APP-USER"));
        assertTrue(mappedRoles.contains("APP-ADMIN"));
        assertTrue(mappedRoles.contains("joe"));

        Iterator<String> iterator = mappedRoles.iterator();
        int count = 0;
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        assertEquals(count, 3);
    }

    @Test
    public void testRegexMapperEmailKeep() {
        Roles roles = createRoles("user@gmail.com", "joe", "user@customerApp.com");
        RegexRoleMapper roleMapper = new RegexRoleMapper.Builder().setPattern(".*@([a-zA-Z]*)\\..*").setReplacement("$1-role").setKeepNonMapped(true).build();
        Roles mappedRoles = roleMapper.mapRoles(roles);

        assertFalse(mappedRoles.contains("user@gmail.com"));
        assertFalse(mappedRoles.contains("user@customerApp.com"));
        assertTrue(mappedRoles.contains("gmail-role"));
        assertTrue(mappedRoles.contains("customerApp-role"));
        assertTrue(mappedRoles.contains("joe"));

        Iterator<String> iterator = mappedRoles.iterator();
        int count = 0;
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        assertEquals(count, 3);
    }

    @Test
    public void testRegexMapperEmailDoNotKeep() {
        Roles roles = createRoles("user@gmail.com", "joe", "user@customerApp.com");
        RegexRoleMapper roleMapper = new RegexRoleMapper.Builder().setPattern(".*@([a-zA-Z]*)\\..*").setReplacement("$1-role").setKeepNonMapped(false).build();
        Roles mappedRoles = roleMapper.mapRoles(roles);

        assertFalse(mappedRoles.contains("user@gmail.com"));
        assertFalse(mappedRoles.contains("user@customerApp.com"));
        assertTrue(mappedRoles.contains("gmail-role"));
        assertTrue(mappedRoles.contains("customerApp-role"));
        assertFalse(mappedRoles.contains("joe"));

        Iterator<String> iterator = mappedRoles.iterator();
        int count = 0;
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        assertEquals(count, 2);
    }

    @Test
    public void testRegexMapperEmailDoNotKeepReplaceAll() {
        Roles roles = createRoles("user@gmail.com", "joe", "user@customerApp.com");
        RegexRoleMapper roleMapper = new RegexRoleMapper.Builder().setPattern(".*@([a-zA-Z]*)\\..*").setReplacement("$1-role").setKeepNonMapped(false).setReplaceAll(true).build();
        Roles mappedRoles = roleMapper.mapRoles(roles);

        assertFalse(mappedRoles.contains("user@gmail.com"));
        assertFalse(mappedRoles.contains("user@customerApp.com"));
        assertTrue(mappedRoles.contains("gmail-role"));
        assertTrue(mappedRoles.contains("customerApp-role"));
        assertFalse(mappedRoles.contains("joe"));

        Iterator<String> iterator = mappedRoles.iterator();
        int count = 0;
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        assertEquals(count, 2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRegexMapperInvalidRegex() {
        new RegexRoleMapper.Builder().setPattern("*-admin").setReplacement("app-$1").build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRegexMapperInvalidReplacement() {
        Roles roles = createRoles("123-admin");
        RegexRoleMapper roleMapper = new RegexRoleMapper.Builder().setPattern(".*-admin").setReplacement("$2").build();
        Roles mappedRoles = roleMapper.mapRoles(roles);
        mappedRoles.contains("application-user");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRegexMapperInvalidEmptyReplacement() {
        new RegexRoleMapper.Builder().setPattern(".*-admin").setReplacement("").build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRegexMapperInvalidEmptyPattern() {
        new RegexRoleMapper.Builder().setPattern("").setReplacement("any").build();
    }

    @Test
    public void testRegexMapperDoNotAlterRoles() {
        Roles roles = createRoles("123-admin");
        RegexRoleMapper roleMapper = new RegexRoleMapper.Builder().setPattern("(.*)").setReplacement("$1").setKeepNonMapped(false).setReplaceAll(true).build();
        Roles mappedRoles = roleMapper.mapRoles(roles);
        assertTrue(mappedRoles.contains("123-admin"));
    }

    @Test
    public void testRegexMapperDoNotAlterRoles2() {
        Roles roles = createRoles("123-admin");
        RegexRoleMapper roleMapper = new RegexRoleMapper.Builder().setPattern("no-role-matches-this-pattern")
                .setReplacement("any").setKeepNonMapped(true).setReplaceAll(true).build();
        Roles mappedRoles = roleMapper.mapRoles(roles);
        assertTrue(mappedRoles.contains("123-admin"));
        assertFalse(mappedRoles.contains("any"));
    }

    @Test
    public void testRegexMapperReplaceAllSubstrings() {
        Roles roles = createRoles("app-guest", "joe", "app-guest-first-time-guest");
        RegexRoleMapper roleMapper = new RegexRoleMapper.Builder().setPattern("guest").setReplacement("user").setKeepNonMapped(false).setReplaceAll(true).build();
        Roles mappedRoles = roleMapper.mapRoles(roles);

        assertFalse(mappedRoles.contains("app-guest"));
        assertFalse(mappedRoles.contains("app-guest-first-time-guest"));
        assertFalse(mappedRoles.contains("app-user-first-time-guest"));
        assertFalse(mappedRoles.contains("app-guest-first-time-user"));
        assertTrue(mappedRoles.contains("app-user"));
        assertTrue(mappedRoles.contains("app-user-first-time-user"));
        assertFalse(mappedRoles.contains("joe"));

        Iterator<String> iterator = mappedRoles.iterator();
        int count = 0;
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        assertEquals(count, 2);
    }

    private Set<String> createSet(String... values) {
        HashSet<String> set = new HashSet<>();
        Collections.addAll(set, values);
        return set;
    }

    private Roles createRoles(String... roles) {
        return Roles.fromSet(createSet(roles));
    }
}
