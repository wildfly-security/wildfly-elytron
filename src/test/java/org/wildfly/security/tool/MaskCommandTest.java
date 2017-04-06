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

import java.security.InvalidAlgorithmParameterException;

import org.junit.Assert;
import org.junit.Ignore;
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
        String retValNoNewLine = retVal.substring(0, retVal.length() - 1);
        assertTrue("output has to be the as pre-generated one", ("MASK-" + pbGenerated + ";" + "ASDF1234" + ";" + 123).equals(retValNoNewLine));
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1057")
    public void testMissingSaltAndIteration() {

        String[] args = { "--secret", "super_secret" };

        String output = executeCommandAndCheckStatusAndGetOutput(args);
        if (!(output.contains("salt") && output.contains("iteration"))) {
            Assert.fail("There must be message about required SALT and ITERATION or at least one of them.");
        }
    }

    @Test
    public void testMissingIteration() {
        String[] args = { "--secret", "super_secret", "--salt", "1234ABCD" };

        try {
            executeCommandAndCheckStatus(args);
            Assert.fail("It must fail.");
        } catch (RuntimeException e) {
            Assert.assertTrue(e.getCause() instanceof IllegalArgumentException);
            Assert.assertEquals(e.getCause().getMessage(),
                "ELY03025: Iteration count not specified for password based encryption");
        }
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1057")
    public void testMissingSalt() {

        String[] args = { "--secret", "super_secret", "--iteration", "123" };

        try {
            executeCommandAndCheckStatus(args);
            Assert.fail("It must fail.");
        } catch (RuntimeException e) {
            Assert.assertTrue(
                String.format("We expect [%s] but was [%s].", IllegalArgumentException.class, e.getCause().getClass()),
                e.getCause() instanceof IllegalArgumentException);
            Assert.assertEquals(e.getCause().getMessage(), "Salt not specified for password based encryption");
        }
    }

    @Test
    public void testWrongSaltLong() {
        int correctSaltByteSize = 8;
        String[] salt = { "12345678", "ABCD1234", "12用戶", "veryLongSaltValue", "short" };

        for (int i = 0; i < salt.length; i++) {
            String[] args = { "--secret", "super_secret", "--salt", salt[i], "--iteration", "123" };
            try {
                executeCommandAndCheckStatus(args);
                if (salt[i].getBytes().length != correctSaltByteSize) {
                    Assert.fail("It must fail.");
                }
            } catch (RuntimeException e) {
                Assert.assertTrue(e.getCause() instanceof InvalidAlgorithmParameterException);
                Assert.assertEquals(e.getCause().getMessage(), "Salt must be 8 bytes long");
            }
        }
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1058")
    public void testIterationAsStringValue() {
        String[] args = { "--secret", "super_secret", "--salt", "1234ABCD", "--iteration", "abcd" };

        try {
            executeCommandAndCheckStatus(args);
            Assert.fail("It must fail.");
        } catch (RuntimeException e) {
            Assert.assertTrue(String.format("[%s]", e.getCause()), e.getCause() instanceof NumberFormatException);
            Assert.assertEquals(e.getCause().getMessage(),
                "Iteration count parser exception");
        }
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1058")
    public void testIterationAsLongMax() {
        String[] args = { "--secret", "super_secret", "--salt", "1234ABCD", "--iteration", String.valueOf(Long.MAX_VALUE) };

        try {
            executeCommandAndCheckStatus(args);
            Assert.fail("It must fail.");
        } catch (RuntimeException e) {
            Assert.assertTrue(String.format("[%s]", e.getCause()), e.getCause() instanceof NumberFormatException);
            Assert.assertEquals(e.getCause().getMessage(), "Iteration count parser exception");
        }
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1059")
    public void testIterationAsNegativeValue() {
        String[] args = { "--secret", "super_secret", "--salt", "1234ABCD", "--iteration", "-123" };
        try {
            executeCommandAndCheckStatus(args);
            Assert.fail("It must fail.");
        } catch (RuntimeException e) {
            Assert.assertTrue(String.format("[%s]", e.getCause()), e.getCause() instanceof NumberFormatException);
            Assert.assertEquals(e.getCause().getMessage(), "Iteration count parser exception");
        }
    }

    @Test
    public void testPrintHelp() {
        String[] args = { "--help" };

        String output = executeCommandAndCheckStatusAndGetOutput(args);
        assertTrue(output.contains("Get help with usage of this command"));
    }

}
