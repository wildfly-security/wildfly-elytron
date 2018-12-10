/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Basic String role mapping tests
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
public class RoleMappingTest {

    @Test
    public void testInitialize() {
        Roles roles = createRoles("foo", "joe");

        MappedRoleMapper roleMapper = new MappedRoleMapper();

        Map<String, String> mappingMap = new LinkedHashMap<>();
        mappingMap.put("foo", "bar role");

        roleMapper.initialize(mappingMap);

        Roles mappedRoles = roleMapper.mapRoles(roles);

        assertTrue(mappedRoles.contains("bar"));
        assertTrue(mappedRoles.contains("role"));
        assertFalse(mappedRoles.contains("foo"));
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
    public void testMappedRoles() {
        Roles roles = createRoles("foo", "joe");

        Map<String, Set<String>> mappingMap = new HashMap<>();
        mappingMap.put("foo", createSet("bar", "role"));

        RoleMapper mapper = new MappedRoleMapper.Builder()
                .setRoleMap(mappingMap).build();

        Roles mappedRoles = mapper.mapRoles(roles);

        assertTrue(mappedRoles.contains("bar"));
        assertTrue(mappedRoles.contains("role"));
        assertFalse(mappedRoles.contains("foo"));
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
    public void testMappedRolesMultipleMappings() {
        Roles roles = createRoles("foo", "joe");

        Map<String, Set<String>> mappingMap = new HashMap<>();
        mappingMap.put("foo", createSet("bar", "role"));
        mappingMap.put("nope", createSet("not", "bar"));
        mappingMap.put("joe", createSet("bar", "foo"));
        RoleMapper mapper = new MappedRoleMapper.Builder()
                .setRoleMap(mappingMap).build();

        Roles mappedRoles = mapper.mapRoles(roles);

        assertTrue(mappedRoles.contains("bar"));
        assertTrue(mappedRoles.contains("role"));
        assertTrue(mappedRoles.contains("foo"));
        assertFalse(mappedRoles.contains("joe"));
        assertFalse(mappedRoles.contains("nope"));
        assertFalse(mappedRoles.contains("not"));

        Iterator<String> iterator = mappedRoles.iterator();
        int count = 0;
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        assertEquals(count, 3);
    }

    @Test
    public void testUnsuccessfulMapping() {
        Roles roles = createRoles("foo", "joe");

        Map<String, Set<String>> mappingMap = new HashMap<>();
        mappingMap.put("nope", createSet("not", "bar"));
        mappingMap.put("bar", createSet("bar", "foo"));
        RoleMapper mapper = new MappedRoleMapper.Builder()
                .setRoleMap(mappingMap).build();

        Roles mappedRoles = mapper.mapRoles(roles);

        assertFalse(mappedRoles.contains("bar"));
        assertFalse(mappedRoles.contains("foo"));
        assertFalse(mappedRoles.contains("joe"));
        assertFalse(mappedRoles.contains("nope"));
        assertFalse(mappedRoles.contains("not"));

        Iterator<String> iterator = mappedRoles.iterator();
        assertFalse(iterator.hasNext());
    }

    @Test
    public void testSuffixRoles() {
        String[] stringRoles = {"foo", "bar"};
        String suffix = "suffix";

        Roles roles = createRoles(stringRoles);

        Roles suffixRoles = roles.addSuffix(suffix);

        for (String s : stringRoles) {
            assertTrue(suffixRoles.contains(s + suffix));
        }

        int count = 0;
        for (Iterator<String> iterator = suffixRoles.iterator(); iterator.hasNext(); ) {
            iterator.next();
            count++;
        }
        assertEquals(count, 2);
    }

    @Test
    public void testPrefixRoles() {
        String[] stringRoles = {"foo", "bar"};
        String prefix = "prefix";

        Roles roles = createRoles(stringRoles);

        Roles prefixRoles = roles.addPrefix(prefix);

        for (String s : stringRoles) {
            assertTrue(prefixRoles.contains(prefix + s));
        }

        int count = 0;
        for (Iterator<String> iterator = prefixRoles.iterator(); iterator.hasNext(); ) {
            iterator.next();
            count++;
        }
        assertEquals(count, 2);
    }

    @Test
    public void testIntersectionRoles() {
        Roles roles1 = createRoles("foo", "bar");
        Roles roles2 = createRoles("role", "foo");

        Roles intersectionRoles = roles1.and(roles2);

        assertTrue(intersectionRoles.contains("foo"));
        assertFalse(intersectionRoles.contains("bar"));
        assertFalse(intersectionRoles.contains("role"));

        int count = 0;
        for (Iterator<String> iterator = intersectionRoles.iterator(); iterator.hasNext(); ) {
            iterator.next();
            count++;
        }
        assertEquals(count, 1);
    }

    @Test
    public void testUnionRoles() {
        Roles roles1 = createRoles("foo", "bar");
        Roles roles2 = createRoles("role", "foo");

        Roles unionRoles = roles1.or(roles2);

        assertTrue(unionRoles.contains("foo"));
        assertTrue(unionRoles.contains("bar"));
        assertTrue(unionRoles.contains("role"));

        int count = 0;
        for (Iterator<String> iterator = unionRoles.iterator(); iterator.hasNext(); ) {
            iterator.next();
            count++;
        }
        assertEquals(count, 3);
    }

    @Test
    public void testDisjunctionRoles() {
        Roles roles1 = createRoles("foo", "bar");
        Roles roles2 = createRoles("role", "foo");

        Roles disjunctionRoles = roles1.xor(roles2);

        assertFalse(disjunctionRoles.contains("foo"));
        assertTrue(disjunctionRoles.contains("bar"));
        assertTrue(disjunctionRoles.contains("role"));

        int count = 0;
        for (Iterator<String> iterator = disjunctionRoles.iterator(); iterator.hasNext(); ) {
            iterator.next();
            count++;
        }
        assertEquals(count, 2);
    }

    @Test
    public void testDifferenceRoles() {
        Roles roles1 = createRoles("foo", "bar");
        Roles roles2 = createRoles("role", "foo");

        Roles unionRoles = roles1.minus(roles2);

        assertFalse(unionRoles.contains("foo"));
        assertTrue(unionRoles.contains("bar"));
        assertFalse(unionRoles.contains("role"));

        int count = 0;
        for (Iterator<String> iterator = unionRoles.iterator(); iterator.hasNext(); ) {
            iterator.next();
            count++;
        }
        assertEquals(count, 1);
    }

    private Set<String> createSet(String... values) {
        HashSet<String> set = new HashSet<>();
        for (String s : values) set.add(s);
        return set;
    }

    private Roles createRoles(String... roles) {
        return Roles.fromSet(createSet(roles));
    }
}

