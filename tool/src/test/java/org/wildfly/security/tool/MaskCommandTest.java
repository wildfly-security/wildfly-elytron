/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.tool;

import static org.junit.Assert.assertTrue;
import static org.wildfly.security.tool.Params.LINE_SEPARATOR;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests for mask command.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 * @author Hynek Švábek <hsvabek@redhat.com>
 */
public class MaskCommandTest extends AbstractCommandTest {

    @Override
    protected String getCommandType() {
        return MaskCommand.MASK_COMMAND;
    }

    /**
     * Basic test to check if output hash is compatible with PicketBox PBE functions.
     * @throws Exception if something goes wrong
     */
    @Test
    public void maskCompatibilityCheck() throws Exception {
        final String secret = "super_secret";
        final String pbGenerated = "088WUKotOwu7VOS8xRj.Rr";  // super_secret;ASDF1234;123

        String[] args = {"--iteration", "123", "--salt", "ASDF1234", "--secret", secret};

        String retVal = executeCommandAndCheckStatusAndGetOutput(args);
        String retValNoNewLine = retVal.substring(0, retVal.indexOf(LINE_SEPARATOR));
        assertTrue("output has to be the as pre-generated one", ("MASK-" + pbGenerated + ";" + "ASDF1234" + ";" + 123).equals(retValNoNewLine));
    }

    @Test
    public void testMissingSaltAndIteration() {
        final String defaultIteration = "10000";

        String[] args = { "--secret", "super_secret" };

        String retVal = executeCommandAndCheckStatusAndGetOutput(args);
        String[] retValLines = retVal.split(LINE_SEPARATOR);

        assertTrue("Message about invalid salt parameter must be present", retValLines[0].contains("Invalid \"salt\" parameter. Generated value"));
        assertTrue("Message about invalid iteration parameter must be present", ("Invalid \"iteration\" parameter. Default value \"" + defaultIteration + "\" will be used.").equals(retValLines[1]));
        assertTrue("Message about invalid salt parameter must be present", retValLines[2].contains("MASK-"));
    }

    @Test
    public void testMissingIteration() {
        final String secret = "super_secret";
        final String salt = "1234ABCD";
        final String defaultIteration = "10000";
        final String pregenerated = "2U6f.QN7bARXA0/hsLXC0H";

        String[] args = { "--secret", secret, "--salt", salt };

        String retVal = executeCommandAndCheckStatusAndGetOutput(args);
        String[] retValLines = retVal.split(LINE_SEPARATOR);

        assertTrue("Message about invalid iteration parameter must be present", ("Invalid \"iteration\" parameter. Default value \"" + defaultIteration + "\" will be used.").equals(retValLines[0]));
        assertTrue("Output has to be the as pre-generated one", ("MASK-" + pregenerated + ";" + salt + ";" + defaultIteration).equals(retValLines[1]));
    }

    @Test
    public void testMissingSalt() {

        String[] args = { "--secret", "super_secret", "--iteration", "123" };

        String retVal = executeCommandAndCheckStatusAndGetOutput(args);
        String[] retValLines = retVal.split(LINE_SEPARATOR);

        assertTrue("Message about invalid salt parameter must be present", retValLines[0].contains("Invalid \"salt\" parameter. Generated value"));
        assertTrue("Message about invalid salt parameter must be present", retValLines[1].contains("MASK-"));
    }

    @Test
    public void testWrongSaltLong() {
        int correctSaltByteSize = 8;
        String[] salt = { "12345678", "ABCD1234", "12用戶", "veryLongSaltValue", "short" };

        for (int i = 0; i < salt.length; i++) {
            String[] args = { "--secret", "super_secret", "--salt", salt[i], "--iteration", "123" };
            try {
                executeCommandAndCheckStatus(args);
                if (salt[i].getBytes(StandardCharsets.UTF_8).length != correctSaltByteSize) {
                    Assert.fail("It must fail.");
                }
            } catch (RuntimeException e) {
                Assert.assertTrue(e.getCause() instanceof InvalidAlgorithmParameterException);
                Assert.assertEquals(e.getCause().getMessage(), "Salt must be 8 bytes long");
            }
        }
    }

    @Test
    public void testIterationAsStringValue() {
        final String secret = "super_secret";
        final String salt = "1234ABCD";
        final String defaultIteration = "10000";
        final String pregenerated = "2U6f.QN7bARXA0/hsLXC0H";

        String[] args = { "--secret", secret, "--salt", salt, "--iteration", "abcd" };

        String retVal = executeCommandAndCheckStatusAndGetOutput(args);
        String[] retValLines = retVal.split(LINE_SEPARATOR);

        assertTrue("IllegalArgumentException must be present", ("java.lang.IllegalArgumentException: ELYTOOL00007: Invalid \"iteration\" value. Must be an integer between 1 and 2147483647, inclusive").equals(retValLines[0]));
        assertTrue("Message about invalid iteration parameter must be present", ("Invalid \"iteration\" parameter. Default value \"" + defaultIteration + "\" will be used.").equals(retValLines[1]));
        assertTrue("Output has to be the as pre-generated one", ("MASK-" + pregenerated + ";" + salt + ";" + defaultIteration).equals(retValLines[2]));
    }

    @Test
    public void testIterationAsLongMax() {
        final String secret = "super_secret";
        final String salt = "1234ABCD";
        final String defaultIteration = "10000";
        final String pregenerated = "2U6f.QN7bARXA0/hsLXC0H";

        String[] args = { "--secret", secret, "--salt", salt, "--iteration", String.valueOf(Long.MAX_VALUE) };

        String retVal = executeCommandAndCheckStatusAndGetOutput(args);
        String[] retValLines = retVal.split(LINE_SEPARATOR);

        assertTrue("IllegalArgumentException must be present", ("java.lang.IllegalArgumentException: ELYTOOL00007: Invalid \"iteration\" value. Must be an integer between 1 and 2147483647, inclusive").equals(retValLines[0]));
        assertTrue("Message about invalid iteration parameter must be present", ("Invalid \"iteration\" parameter. Default value \"" + defaultIteration + "\" will be used.").equals(retValLines[1]));
        assertTrue("Output has to be the as pre-generated one", ("MASK-" + pregenerated + ";" + salt + ";" + defaultIteration).equals(retValLines[2]));
    }

    @Test
    public void testIterationAsNegativeValue() {
        final String secret = "super_secret";
        final String salt = "1234ABCD";
        final String defaultIteration = "10000";
        final String pregenerated = "2U6f.QN7bARXA0/hsLXC0H";

        String[] args = { "--secret", secret, "--salt", salt, "--iteration", "-123" };

        String retVal = executeCommandAndCheckStatusAndGetOutput(args);
        String[] retValLines = retVal.split(LINE_SEPARATOR);

        assertTrue("IllegalArgumentException must be present", ("java.lang.IllegalArgumentException: ELYTOOL00007: Invalid \"iteration\" value. Must be an integer between 1 and 2147483647, inclusive").equals(retValLines[0]));
        assertTrue("Message about invalid iteration parameter must be present", ("Invalid \"iteration\" parameter. Default value \"" + defaultIteration + "\" will be used.").equals(retValLines[1]));
        assertTrue("Output has to be the as pre-generated one", ("MASK-" + pregenerated + ";" + salt + ";" + defaultIteration).equals(retValLines[2]));
    }

    @Test
    public void testPrintHelp() {
        assertTrue(executeCommandAndCheckStatusAndGetOutput(new String[]{"--help"})
                .contains("Get help with usage of this command"));
        assertTrue(executeCommandAndCheckStatusAndGetOutput(new String[]{"--help","-x", "sec", "-s", "12345678"})
                .contains("Get help with usage of this command"));
    }

    @Test
    public void testDuplicateOptions() {
        final String secret = "super_secret";

        String[] args = {"--iteration", "123", "--salt", "ASDF1234", "--secret", secret, "--secret", "another_secret", "-s", "another_salt"};

        String output = executeCommandAndCheckStatusAndGetOutput(args);

        Assert.assertTrue(output.contains("Option \"salt\" specified more than once. Only the first occurrence will be used."));
        Assert.assertTrue(output.contains("Option \"secret\" specified more than once. Only the first occurrence will be used."));
        Assert.assertFalse(output.contains("Option \"iteration\" specified more than once. Only the first occurrence will be used"));
    }
}
