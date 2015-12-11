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
package org.wildfly.security.credential.external.impl;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.external.ExternalCredentialException;
import org.wildfly.security.credential.store.CredentialStorePermission;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class CmdCredentialProvider extends ExecCredentialProvider {

    /**
     * Default constructor
     */
    public CmdCredentialProvider() {
        SUPPORTED_CMD_TYPE = "CMD";
    }

    /**
     * Executes command in operating system. In case of Java Security Manager active uses
     * doPrivileged to start the command.
     * @param cmd command as operating system accepts
     * @return {@link Credential} transformed using {@link ExternalCredentialProvider#createCredentialFromPassword(char[])}
     * @throws ExternalCredentialException when something goes wrong
     */
    Credential execute(String cmd) throws ExternalCredentialException {

        final SecurityManager sm = System.getSecurityManager();
        CmdRuntimeActions action;
        if (sm != null) {
            sm.checkPermission(CredentialStorePermission.LOAD_EXTERNAL_STORE_PASSWORD);
            action = CmdRuntimeActions.PRIVILEGED;
        } else {
            action = CmdRuntimeActions.NON_PRIVILEGED;
        }

        try {
            return createCredentialFromPassword(action.execCmd(cmd));
        } catch (Exception e) {
            throw log.passwordCommandExecutionProblem(
                    log.isInfoEnabled() ? cmd : "not shown", e);
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
