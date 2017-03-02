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

import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * Test for "credential-store" command.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class CredentialStoreCommandTest extends BaseToolTest {

    /**
     * temporary folder
     */
    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    /**
     * basic test with --password option.
     * @throws Exception if something goes wrong
     */
    @Test
    public void clearTextCSPassword() throws Exception {
        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND);

        String storeFileName  = tmp.getRoot().getAbsolutePath() + "/test.store";

        String[] args = {"--location=" + storeFileName, "--uri=cr-store://test?create=true",
                "--add", "testalias", "--secret", "secret2", "--summary", "--password", "cspassword"};
        command.execute(args);
        assertEquals("returned command status has to be 0", command.getStatus(), ElytronTool.ElytronToolExitStatus_OK);
    }

    /**
     * basic test with --password and masking password options.
     * @throws Exception if something goes wrong
     */
    @Test
    public void maskCSPassword() throws Exception {
        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND);

        String storeFileName  = tmp.getRoot().getAbsolutePath() + "/test.store";

        String[] args = {"--location=" + storeFileName, "--uri=cr-store://test?create=true",
                "--add", "testalias", "--secret", "secret2", "--summary", "--password", "cspassword", "--salt", "A1B2C3D4", "--iteration", "100"};

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        PrintStream original = System.out;
        System.setOut(new PrintStream(result));
        command.execute(args);
        System.setOut(original);
        System.out.println("result" + result.toString());
        assertEquals("returned command status has to be 0", command.getStatus(), ElytronTool.ElytronToolExitStatus_OK);
        assertTrue(result.toString().contains("MASK-"));
    }

    /**
     * basic test without --password option.
     * @throws Exception if something goes wrong
     */
    @Ignore("Issue #15 - bypass prompting using callback handler")
    @Test(expected = CredentialStoreException.class)
    public void noPasswordSpecified() throws Exception {
        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND);

        String storeFileName  = tmp.getRoot().getAbsolutePath() + "/test.store";

        String[] args = {"--location=" + storeFileName, "--uri=cr-store://test?create=true",
                "--add", "testalias", "--secret", "secret2", "--summary", "--salt", "A1B2C3D4", "--iteration", "100"};

        command.execute(args);
    }

}
