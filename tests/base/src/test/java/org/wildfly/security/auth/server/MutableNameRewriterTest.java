/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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
import org.wildfly.security.auth.util.CaseNameRewriter;
import org.wildfly.security.auth.util.MutableNameRewriter;
import org.wildfly.security.auth.util.RegexNameRewriter;

import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class MutableNameRewriterTest {

    private static final String LOWER_CASE_USER_NAME = "user";
    private static final String UPPER_CASE_USER_NAME = "USER";

    private static final String BEFORE_REPLACE_USER_NAME = ".user.";
    private static final String AFTER_REPLACE_ALL_USER_NAME = "dotuserdot";
    private static final String AFTER_REPLACE_USER_NAME = "dotuser.";

    @Test
    public void testMutableNameRewriterWithCaseNameRewriter() {
        CaseNameRewriter caseNameRewriter = new CaseNameRewriter(true);
        MutableNameRewriter rewriter = new MutableNameRewriter(caseNameRewriter);
        String adjustedName = rewriter.rewriteName(LOWER_CASE_USER_NAME);
        assertEquals(UPPER_CASE_USER_NAME, adjustedName);

        caseNameRewriter = new CaseNameRewriter(false);
        rewriter.setTarget(caseNameRewriter);
        adjustedName = rewriter.rewriteName(UPPER_CASE_USER_NAME);
        assertEquals(LOWER_CASE_USER_NAME, adjustedName);

        caseNameRewriter = new CaseNameRewriter();
        rewriter.setTarget(caseNameRewriter);
        adjustedName = rewriter.rewriteName(LOWER_CASE_USER_NAME);
        assertEquals(UPPER_CASE_USER_NAME, adjustedName);
    }

    @Test
    public void testMutableNameRewriterWithRegexNameRewriter() {
        Pattern pattern = Pattern.compile("\\.");

        RegexNameRewriter regexNameRewriter = new RegexNameRewriter(pattern, "dot", true);
        MutableNameRewriter rewriter = new MutableNameRewriter(regexNameRewriter);
        String adjustedName = rewriter.rewriteName(BEFORE_REPLACE_USER_NAME);
        assertEquals(AFTER_REPLACE_ALL_USER_NAME, adjustedName);

        regexNameRewriter = new RegexNameRewriter(pattern, "dot", false);
        rewriter.setTarget(regexNameRewriter);
        adjustedName = rewriter.rewriteName(BEFORE_REPLACE_USER_NAME);
        assertEquals(AFTER_REPLACE_USER_NAME, adjustedName);
    }

    @Test
    public void testMutableNameRewriterExistingUser() throws Exception {
        FileSystemSecurityRealm fileSystemSecurityRealm = new FileSystemSecurityRealm(ServerUtils.getRootPath(true, getClass()));
        ServerUtils.addUser(fileSystemSecurityRealm, "USER");

        CaseNameRewriter caseNameRewriter = new CaseNameRewriter(true);
        MutableNameRewriter mutableNameRewriter = new MutableNameRewriter(caseNameRewriter);
        SecurityDomain domainWithRewriter = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .setPreRealmRewriter(mutableNameRewriter)
                .build();
        ServerAuthenticationContext sac1 = domainWithRewriter.createNewAuthenticationContext();
        sac1.setAuthenticationName("user");
        assertTrue(sac1.authorize());

        SecurityDomain domainWithoutRewriter = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .build();
        ServerAuthenticationContext sac2 = domainWithoutRewriter.createNewAuthenticationContext();
        sac2.setAuthenticationName("user");
        assertFalse(sac2.authorize());
    }
}