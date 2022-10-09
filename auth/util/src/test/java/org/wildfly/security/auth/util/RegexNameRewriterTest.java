package org.wildfly.security.auth.util;

import org.junit.Test;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;

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
