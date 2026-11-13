/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2025 Red Hat, Inc., and individual contributors
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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * @author <a href="mailto:pesilva@redhat.com">Pedro Hos</a>
 *
 */
public class PropertiesMappedRoleMapperTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void testPropertiesRoleMapperWithMappedRole() {
        Roles roles = createRoles("joe", "admin", "enterprise-role");
        URL resource = getClass().getResource("rolesMapping-roles.properties");
        PropertiesMappedRoleMapper mapper = new PropertiesMappedRoleMapper.Builder().rootPath(resource.getPath()).build();
        Roles mapRoles = mapper.mapRoles(roles);

        assertTrue(mapRoles.contains("role-1"));
        assertTrue(mapRoles.contains("role-abc"));
        assertTrue(mapRoles.contains("enterprise-role"));
        assertTrue(mapRoles.contains("admin"));
        assertTrue(mapRoles.contains("joe"));

    }

    @Test
    public void testPropertiesRoleMapperWithoutMappedRole() {
        Roles roles = createRoles("joe", "admin");
        URL resource = getClass().getResource("rolesMapping-roles.properties");
        PropertiesMappedRoleMapper mapper = new PropertiesMappedRoleMapper.Builder().rootPath(resource.getPath()).build();
        Roles mapRoles = mapper.mapRoles(roles);

        assertTrue(mapRoles.contains("admin"));
        assertTrue(mapRoles.contains("joe"));
        assertFalse(mapRoles.contains("role-1"));
        assertFalse(mapRoles.contains("role-abc"));
        assertFalse(mapRoles.contains("enterprise-role"));

    }

    @Test
    public void testPropertiesRoleMapperWrongPropertiesPath() {
        URL resource = getClass().getResource("rolesMapping-roles.properties");
        Exception exception = assertThrows(IllegalStateException.class, () -> {
            new PropertiesMappedRoleMapper.Builder().rootPath(resource.getPath() + "-wrong").build();
        });

        String actualMessage = exception.getMessage();
        assertTrue(actualMessage.equals("ELY16006: Can not read the provided properties file."));

    }

    @Test
    public void testMappingsLoadedOnce() throws IOException {
        File file = tmp.newFile("roles.properties");
        try (InputStream in = getClass().getResourceAsStream("rolesMapping-roles.properties")) {
            Files.copy(in, file.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
        PropertiesMappedRoleMapper mapper = new PropertiesMappedRoleMapper.Builder().rootPath(file.getPath()).build();

        // Changing the file after the mapper is built has no effect.
        Files.write(file.toPath(), "enterprise-role=other-role".getBytes(StandardCharsets.UTF_8));
        Roles mapRoles = mapper.mapRoles(createRoles("enterprise-role"));
        assertTrue(mapRoles.contains("role-1"));
        assertTrue(mapRoles.contains("role-abc"));
        assertFalse(mapRoles.contains("other-role"));

        // Deleting it has no effect either.
        assertTrue(file.delete());
        mapRoles = mapper.mapRoles(createRoles("enterprise-role"));
        assertTrue(mapRoles.contains("role-1"));
        assertTrue(mapRoles.contains("role-abc"));
    }

    private Roles createRoles(String... roles) {
        return Roles.fromSet(createSet(roles));
    }

    private Set<String> createSet(String... values) {
        HashSet<String> set = new HashSet<>();
        Collections.addAll(set, values);
        return set;
    }
}
