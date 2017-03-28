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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.Test;

/**
 * Tests for mask command.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class MaskCommandTest extends BaseToolTest {

    /**
     * Basic test to check if output hash is compatible with PicketBox PBE functions.
     * @throws Exception if something goes wrong
     */
    @Test
    public void maskCompatibilityCheck() throws Exception {

        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(MaskCommand.MASK_COMMAND);

        final String secret = "super_secret";
        final String pbGenerated = "088WUKotOwu7VOS8xRj.Rr";  // super_secret;ASDF1234;123

        String[] args = {"--iteration", "123", "--salt", "ASDF1234", "--secret", secret};

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        PrintStream original = System.out;
        System.setOut(new PrintStream(result));
        command.execute(args);
        System.setOut(original);
        String retVal = result.toString();
        String retValNoNewLine = retVal.substring(0, retVal.length() - 1);
        assertEquals("returned command status has to be 0", command.getStatus(), ElytronTool.ElytronToolExitStatus_OK);
        assertTrue("output has to be the as pre-generated one", ("MASK-" + pbGenerated + ";" + "ASDF1234" + ";" + 123).equals(retValNoNewLine));
    }

}
