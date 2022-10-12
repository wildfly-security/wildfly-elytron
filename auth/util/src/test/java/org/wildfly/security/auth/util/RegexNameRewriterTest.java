/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.auth.util;

import static org.junit.Assert.assertEquals;

import java.util.regex.Pattern;

import org.junit.Test;

public class RegexNameRewriterTest {

    private static final String BEFORE_REPLACE_USER_NAME = ".user.";
    private static final String AFTER_REPLACE_ALL_USER_NAME = "dotuserdot";
    private static final String AFTER_REPLACE_USER_NAME = "dotuser.";

    @Test
    public void testRegexNameRewriter() {
        Pattern pattern = Pattern.compile("\\.");

        RegexNameRewriter regexNameRewriter = new RegexNameRewriter(pattern, "dot", true);
        String regexName = regexNameRewriter.rewriteName(BEFORE_REPLACE_USER_NAME);
        assertEquals(AFTER_REPLACE_ALL_USER_NAME, regexName);

        regexNameRewriter = new RegexNameRewriter(pattern, "dot", false);
        regexName = regexNameRewriter.rewriteName(BEFORE_REPLACE_USER_NAME);
        assertEquals(AFTER_REPLACE_USER_NAME, regexName);
    }

}
