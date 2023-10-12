/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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

import org.junit.Test;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CustomNameRewriterTest {

    private static final String BEFORE_USER_NAME = "Bob";
    private static final String AFTER_USER_NAME = "Robert";

    @Test
    public void testCustomNameRewriter() {
        CustomNameRewriter rewriter = new CustomNameRewriter();
        String adjustedName = rewriter.rewriteName(BEFORE_USER_NAME);
        assertEquals(AFTER_USER_NAME, adjustedName);
    }

    @Test
    public void testCustomNameRewriterAuthentication() throws Exception {
        FileSystemSecurityRealm fileSystemSecurityRealm = createSecurityRealm();
        CustomNameRewriter rewriter = new CustomNameRewriter();
        SecurityDomain domainWithRewriter = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .setPreRealmRewriter(rewriter)
                .build();
        ServerAuthenticationContext sac1 = domainWithRewriter.createNewAuthenticationContext();
        sac1.setAuthenticationName(BEFORE_USER_NAME); // security domain contains the user "Robert"
        assertTrue(sac1.authorize());

        SecurityDomain domainWithoutRewriter = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .build();
        ServerAuthenticationContext sac2 = domainWithoutRewriter.createNewAuthenticationContext();
        sac2.setAuthenticationName(BEFORE_USER_NAME); // should fail if rewriter not configured
        assertFalse(sac2.authorize());
    }

    @Test
    public void testCustomNameRewriterNonExistingUser() throws Exception{
        FileSystemSecurityRealm fileSystemSecurityRealm = createSecurityRealm();
        CustomNameRewriter rewriter = new CustomNameRewriter();
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .setPreRealmRewriter(rewriter)
                .build();
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        sac.setAuthenticationName("John");
        assertFalse(sac.authorize());
    }

    private FileSystemSecurityRealm createSecurityRealm() throws Exception {
        FileSystemSecurityRealm realm = new FileSystemSecurityRealm(ServerUtils.getRootPath(true, getClass()));
        ServerUtils.addUser(realm, AFTER_USER_NAME);
        return realm;
    }

    private final class CustomNameRewriter implements NameRewriter {

        @Override
        public String rewriteName(String original) {
            if (original == null) {
                return null;
            } else if (original.equals(BEFORE_USER_NAME)) {
                return AFTER_USER_NAME;
            } else {
                return original;
            }
        }
    }
}
