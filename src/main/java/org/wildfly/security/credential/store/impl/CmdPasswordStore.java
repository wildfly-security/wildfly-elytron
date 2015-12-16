/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.credential.store.impl;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.StringTokenizer;

import org.wildfly.security.credential.store.CredentialStorePermission;
import org.wildfly.security.credential.store.CredentialStoreSpi;

/**
 * Pseudo credential store which is able to get credential from output of executed program.
 * It uses comma as parameter delimiter to be able to handle more complicated use cases.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class CmdPasswordStore extends CommandCredentialStore {

    /**
     * Type of {@link CredentialStoreSpi} implementation. Will be used as algorithm name when registering service in
     * {@link org.wildfly.security.WildFlyElytronProvider}.
     */
    public static final String CMD_PASSWORD_STORE = "CmdPasswordStore";
    /**
     * Supported command type.
     */
    public static final String SUPPORTED_CMD_TYPE = "CMD";

    /**
     * Default constructor.
     */
    public CmdPasswordStore() {
        storeName = "cmd";
    }

    /**
     * Executes command in operating system using {@link Runtime#exec(String)} method. Grabs the output and return it for further processing.
     * In case of Java Security Manager active uses doPrivileged to start the command.
     * @param passwordCommand command as operating system accepts
     * @return output from the {@link Process} resulting of command execution
     * @throws Throwable when something goes wrong
     */
    @Override
    char[] executePasswordCommand(String passwordCommand) throws Throwable {

        final SecurityManager sm = System.getSecurityManager();
        CmdRuntimeActions action;
        if (sm != null) {
            sm.checkPermission(CredentialStorePermission.LOAD_EXTERNAL_STORE_PASSWORD);
            action = CmdRuntimeActions.PRIVILEGED;
        } else {
            action = CmdRuntimeActions.NON_PRIVILEGED;
        }

        String passwordCmdType;
        String passwordCmdLine;

        // Look for a {...} prefix indicating a password command
        if (passwordCommand.trim().startsWith("{" + SUPPORTED_CMD_TYPE)) {
            StringTokenizer tokenizer = new StringTokenizer(passwordCommand, "{}");
            passwordCmdType = tokenizer.nextToken();
            passwordCmdLine = tokenizer.nextToken();
        } else {
            passwordCmdType = SUPPORTED_CMD_TYPE;
            passwordCmdLine = passwordCommand;
        }

        if (!passwordCmdType.equals(SUPPORTED_CMD_TYPE)) {
            throw log.cacheForExternalCommandsNotSupported();
        }

        try {
            return action.execCmd(passwordCmdLine);
        } catch (Exception e) {
            throw log.passwordCommandExecutionProblem(
                    getName(), e);
        }
    }


    private interface CmdRuntimeActions {

        CmdRuntimeActions NON_PRIVILEGED = new CmdRuntimeActions() {
            public char[] execCmd(final String command) throws Exception {
                final ProcessBuilder builder = new ProcessBuilder(parseCommand(command));
                final Process process = builder.start();
                final String line;
                BufferedReader reader = null;
                try {
                    reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    line = reader.readLine();
                } finally {
                    if (reader != null)
                        reader.close();
                }

                int exitCode = process.waitFor();
                if (log.isTraceEnabled())
                    log.tracef("Exit code from password command = %d", Integer.valueOf(exitCode));
                return line != null ? line.toCharArray() : null;
            }

            protected String[] parseCommand(String command) {
                // comma can be back slashed
                final String[] parsedCommand = command.split("(?<!\\\\),");
                for (int k = 0; k < parsedCommand.length; k++) {
                    if (parsedCommand[k].indexOf('\\') != -1)
                        parsedCommand[k] = parsedCommand[k].replaceAll("\\\\,", ",");
                }
                return parsedCommand;
            }

        };

        CmdRuntimeActions PRIVILEGED = command -> {
            try {
                char[] password = AccessController.doPrivileged((PrivilegedExceptionAction<char[]>) () -> NON_PRIVILEGED.execCmd(command));
                return password;
            } catch (PrivilegedActionException e) {
                throw e.getException();
            }
        };

        char[] execCmd(String cmd) throws Exception;
    }

}
