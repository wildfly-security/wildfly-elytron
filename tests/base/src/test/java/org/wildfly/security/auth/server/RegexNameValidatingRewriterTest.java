/*
 * JBoss, Home of Professional Open Source
 * Copyright 2022 Red Hat, Inc., and individual contributors
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
import org.wildfly.security.auth.util.RegexNameValidatingRewriter;

import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class RegexNameValidatingRewriterTest {

    private static final String ANONYMOUS = "anonymous";
    private static final String MATCHING_USER_NAME = ".user.";
    private static final String NOT_MATCHING_USER_NAME = "user.";

    private Pattern pattern = Pattern.compile("^\\.[a-zA-Z0-9.-]+\\.$");

    @Test
    public void testMatchingRegexNameValidatingRewriter() {
        RegexNameValidatingRewriter regexNameValidatingRewriter = new RegexNameValidatingRewriter(pattern, true);
        String adjustedName = regexNameValidatingRewriter.rewriteName(MATCHING_USER_NAME);
        assertEquals(MATCHING_USER_NAME, adjustedName);

        regexNameValidatingRewriter = new RegexNameValidatingRewriter(pattern, false);
        adjustedName = regexNameValidatingRewriter.rewriteName(MATCHING_USER_NAME);
        assertEquals(null, adjustedName);
    }

    @Test
    public void testNotMatchingRegexNameValidatingRewriter() {
        RegexNameValidatingRewriter regexNameValidatingRewriter = new RegexNameValidatingRewriter(pattern, true);
        String adjustedName = regexNameValidatingRewriter.rewriteName(NOT_MATCHING_USER_NAME);
        assertEquals(null, adjustedName);

        regexNameValidatingRewriter = new RegexNameValidatingRewriter(pattern, false);
        adjustedName = regexNameValidatingRewriter.rewriteName(NOT_MATCHING_USER_NAME);
        assertEquals(NOT_MATCHING_USER_NAME, adjustedName);
    }

    @Test
    public void testMatchingRegexNameValidatingRewriterExistingUser() throws Exception {
        FileSystemSecurityRealm fileSystemSecurityRealm = new FileSystemSecurityRealm(ServerUtils.getRootPath(true, getClass()));
        ServerUtils.addUser(fileSystemSecurityRealm, MATCHING_USER_NAME);

        RegexNameValidatingRewriter regexNameValidatingRewriter = new RegexNameValidatingRewriter(pattern, true);
        SecurityDomain domainWithRewriter = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .setPreRealmRewriter(regexNameValidatingRewriter)
                .build();
        ServerAuthenticationContext sac1 = domainWithRewriter.createNewAuthenticationContext();
        sac1.setAuthenticationName(MATCHING_USER_NAME);
        assertTrue(sac1.authorize());
        assertEquals(MATCHING_USER_NAME, sac1.getAuthorizedIdentity().getPrincipal().getName());
    }

    @Test
    public void testNotMatchingRegexNameValidatingRewriterExistingUser() throws Exception {
        FileSystemSecurityRealm fileSystemSecurityRealm = new FileSystemSecurityRealm(ServerUtils.getRootPath(true, getClass()));
        ServerUtils.addUser(fileSystemSecurityRealm, NOT_MATCHING_USER_NAME);

        RegexNameValidatingRewriter regexNameValidatingRewriter = new RegexNameValidatingRewriter(pattern, true);
        SecurityDomain domainWithRewriter = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .setPreRealmRewriter(regexNameValidatingRewriter)
                .build();
        ServerAuthenticationContext sac1 = domainWithRewriter.createNewAuthenticationContext();
        sac1.setAuthenticationName(NOT_MATCHING_USER_NAME);
        assertTrue(sac1.authorize());
        assertEquals(ANONYMOUS, sac1.getAuthorizedIdentity().getPrincipal().getName());
    }
}
