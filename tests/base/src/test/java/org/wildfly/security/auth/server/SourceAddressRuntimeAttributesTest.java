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
package org.wildfly.security.auth.server;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.authz.RoleDecoder.KEY_SOURCE_ADDRESS;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Collections;

import org.junit.Test;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.authz.SourceAddressRoleDecoder;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * Tests for role decoding with the source IP address runtime attribute.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class SourceAddressRuntimeAttributesTest {

    @Test
    public void testRoleDecodingWithSourceAddressMatch() throws Exception {
        FileSystemSecurityRealm fileSystemSecurityRealm = createSecurityRealm();
        String sourceAddress = "10.12.14.16";
        SourceAddressRoleDecoder roleDecoder = new SourceAddressRoleDecoder(sourceAddress, Roles.of("Admin"));
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper((permissionMappable, roles) -> roles.contains("Admin") ? LoginPermission.getInstance() : PermissionVerifier.NONE)
                .setRoleDecoder(roleDecoder)
                .build();

        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        sac.setAuthenticationName("bob");
        assertFalse(sac.authorize()); // based on the security realm alone, bob does not have "Admin" role

        // make use of the runtime source IP address attribute
        sac = securityDomain.createNewAuthenticationContext();
        sac.addRuntimeAttributes(createRuntimeAttributes(sourceAddress));
        sac.setAuthenticationName("bob");
        assertTrue(sac.authorize());

        // runtime source IP address attribute not specified
        sac = securityDomain.createNewAuthenticationContext();
        sac.addRuntimeAttributes(createRuntimeAttributes(null));
        sac.setAuthenticationName("bob");
        assertFalse(sac.authorize());

        sac = securityDomain.createNewAuthenticationContext();
        sac.setAuthenticationName("alice");
        assertTrue(sac.authorize()); // based on the security realm alone, alice already has "Admin" role

        // make use of the runtime source IP address attribute, make sure alice still has "Admin" role
        sac = securityDomain.createNewAuthenticationContext();
        sac.addRuntimeAttributes(createRuntimeAttributes(sourceAddress));
        sac.setAuthenticationName("alice");
        assertTrue(sac.authorize());

        // make use of the runtime source IP address attribute, make sure alice still has "Admin" role
        sac = securityDomain.createNewAuthenticationContext();
        sac.addRuntimeAttributes(createRuntimeAttributes(null));
        sac.setAuthenticationName("alice");
        assertTrue(sac.authorize());
    }

    @Test
    public void testRoleDecodingWithSourceAddressMismatch() throws Exception {
        FileSystemSecurityRealm fileSystemSecurityRealm = createSecurityRealm();
        String sourceAddress = "10.12.14.16";
        SourceAddressRoleDecoder roleDecoder = new SourceAddressRoleDecoder(sourceAddress, Roles.of("Admin"));
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper((permissionMappable, roles) -> roles.contains("Admin") ? LoginPermission.getInstance() : PermissionVerifier.NONE)
                .setRoleDecoder(roleDecoder)
                .build();

        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        sac.setAuthenticationName("bob");
        assertFalse(sac.authorize()); // based on the security realm alone, bob does not have "Admin" role

        // make use of the runtime source IP address attribute
        sac = securityDomain.createNewAuthenticationContext();
        sac.addRuntimeAttributes(createRuntimeAttributes("10.12.16.16"));
        sac.setAuthenticationName("bob");
        assertFalse(sac.authorize());

        sac = securityDomain.createNewAuthenticationContext();
        sac.setAuthenticationName("alice");
        assertTrue(sac.authorize()); // based on the security realm alone, alice already has "Admin" role

        // make use of the runtime source IP address attribute, make sure alice still has "Admin" role
        sac = securityDomain.createNewAuthenticationContext();
        sac.addRuntimeAttributes(createRuntimeAttributes("10.12.16.16"));
        sac.setAuthenticationName("alice");
        assertTrue(sac.authorize());
    }

    private FileSystemSecurityRealm createSecurityRealm() throws Exception {
        FileSystemSecurityRealm realm = new FileSystemSecurityRealm(getRootPath(true));
        addUser(realm, "alice", "Admin");
        addUser(realm, "bob", "Employee");
        return realm;
    }

    private Path getRootPath(boolean deleteIfExists) throws Exception {
        Path rootPath = Paths.get(getClass().getResource(File.separator).toURI())
                .resolve("filesystem-realm");

        if (rootPath.toFile().exists() && !deleteIfExists) {
            return rootPath;
        }

        return Files.walkFileTree(Files.createDirectories(rootPath), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private void addUser(ModifiableSecurityRealm realm, String userName, String roles) throws RealmUnavailableException {
        MapAttributes attributes = new MapAttributes();
        attributes.addAll(RoleDecoder.KEY_ROLES, Collections.singletonList(roles));

        ModifiableRealmIdentity realmIdentity = realm.getRealmIdentityForUpdate(new NamePrincipal(userName));
        realmIdentity.create();
        realmIdentity.setAttributes(attributes);
        realmIdentity.dispose();
    }

    private Attributes createRuntimeAttributes(String actualSourceAddress) {
        MapAttributes runtimeAttributes = new MapAttributes();
        if (actualSourceAddress != null) {
            runtimeAttributes.addFirst(KEY_SOURCE_ADDRESS, actualSourceAddress);
        }
        return runtimeAttributes;
    }

}
