/*
 * JBoss, Home of Professional Open Source
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import org.junit.Test;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.util.CaseNameRewriter;

/**
 * Tests CaseNameRewriter which adjusts a principal to upper or lower case
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana Calles</a>
 */
public class CaseNameRewriterTest {

    private static final String LOWER_CASE_USER_NAME = "hellouser";
    private static final String UPPER_CASE_USER_NAME = "HELLOUSER";


    @Test
    public void testUpperCaseNameRewriter() {
        CaseNameRewriter rewriter = new CaseNameRewriter(true);
        String adjustedName = rewriter.rewriteName(LOWER_CASE_USER_NAME);
        assertEquals(UPPER_CASE_USER_NAME, adjustedName);
    }

    @Test
    public void testUpperCaseNameRewriterDefaultBehaviour() {
        CaseNameRewriter rewriter = new CaseNameRewriter();
        String adjustedName = rewriter.rewriteName(LOWER_CASE_USER_NAME);
        assertEquals(UPPER_CASE_USER_NAME, adjustedName);
    }

    @Test
    public void testLowerCaseNameRewriter() {
        CaseNameRewriter rewriter = new CaseNameRewriter(false);
        String adjustedName = rewriter.rewriteName(UPPER_CASE_USER_NAME);
        assertEquals(LOWER_CASE_USER_NAME, adjustedName);
    }

    @Test
    public void testCaseNameRewriterExistingUserUpperCase() throws Exception {
        FileSystemSecurityRealm fileSystemSecurityRealm = createSecurityRealm();
        CaseNameRewriter rewriter = new CaseNameRewriter(true);
        SecurityDomain domainWithRewriter = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .setPreRealmRewriter(rewriter)
                .build();
        ServerAuthenticationContext sac1 = domainWithRewriter.createNewAuthenticationContext();
        sac1.setAuthenticationName("alice");    // security domain contains the user "ALICE"
        assertTrue(sac1.authorize());

        SecurityDomain domainWithoutRewriter = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .build();
        ServerAuthenticationContext sac2 = domainWithoutRewriter.createNewAuthenticationContext();
        sac2.setAuthenticationName("alice"); // should fail if rewriter not configured
        assertFalse(sac2.authorize());
    }

    @Test
    public void testCaseNameRewriterExistingUserLowerCase() throws Exception {
        FileSystemSecurityRealm fileSystemSecurityRealm = createSecurityRealm();
        CaseNameRewriter rewriter = new CaseNameRewriter(false);
        SecurityDomain domainWithRewriter = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .setPreRealmRewriter(rewriter)
                .build();
        ServerAuthenticationContext sac1 = domainWithRewriter.createNewAuthenticationContext();
        sac1.setAuthenticationName("JOHN");    // security domain contains the user "john"
        assertTrue(sac1.authorize());

        SecurityDomain domainWithoutRewriter = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .build();
        ServerAuthenticationContext sac2 = domainWithoutRewriter.createNewAuthenticationContext();
        sac2.setAuthenticationName("JOHN"); // should fail if rewriter not configured
        assertFalse(sac2.authorize());
    }

    @Test
    public void testCaseNameRewriterNonExistingUser() throws Exception{
        FileSystemSecurityRealm fileSystemSecurityRealm = createSecurityRealm();
        CaseNameRewriter rewriter = new CaseNameRewriter(true);
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .setPreRealmRewriter(rewriter)
                .build();
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        sac.setAuthenticationName("bob");
        assertFalse(sac.authorize());
    }

    private FileSystemSecurityRealm createSecurityRealm() throws Exception {
        FileSystemSecurityRealm realm = new FileSystemSecurityRealm(getRootPath(true));
        addUser(realm, "ALICE");
        addUser(realm, "john");
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

    private void addUser(ModifiableSecurityRealm realm, String userName) throws RealmUnavailableException {
        ModifiableRealmIdentity realmIdentity = realm.getRealmIdentityForUpdate(new NamePrincipal(userName));
        realmIdentity.create();
        realmIdentity.dispose();
    }
}
