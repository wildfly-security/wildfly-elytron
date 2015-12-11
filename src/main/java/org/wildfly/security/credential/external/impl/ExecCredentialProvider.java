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

import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.external.ExternalCredentialException;
import org.wildfly.security.credential.store.CredentialStorePermission;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * {@link org.wildfly.security.credential.external.ExternalCredentialSpi} implementation which supports getting
 * credentials using {@code Runtime#exec} method.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class ExecCredentialProvider extends ExternalCredentialProvider {

    /**
     * Parameter name which denotes command line
     */
    public static final String COMMAND_LINE = "exec.command";
    /**
     * Parameter name which denotes execution type
     */
    public static final String EXEC_TYPE = "exec.type";

    String SUPPORTED_CMD_TYPE = "EXT";

    static final Set<String> SUPPORTED_PARAMETERS = Collections.unmodifiableSet(new HashSet<>(
            Arrays.asList(EXEC_TYPE, COMMAND_LINE)));

    @Override
    public <C extends Credential> C resolveCredential(Map<String, String> parameters, Class<C> credentialType) throws ExternalCredentialException {
        String passwordCommand = parameters.get(COMMAND_LINE);
        String execType = parameters.get(EXEC_TYPE);

        if (execType != null && !execType.equals(SUPPORTED_CMD_TYPE)) {
            throw log.executionTypeNotSupported(execType);
        }

        if (passwordCommand != null) {
            return credentialType.cast(execute(passwordCommand));
        } else {
            throw log.passwordCommandNotSpecified();
        }
    }

    @Override
    public <C extends Credential> C resolveCredential(String passwordCommand, Class<C> credentialType) throws ExternalCredentialException {

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

        return credentialType.cast(execute(passwordCmdLine));
    }

    /**
     * This method provides parameters supported by external credential provider. The {@code Set} can be used
     * to filter parameters supplied {@link #resolveCredential(Map, Class)} or {@link #resolveCredential(String, Class)}
     * methods.
     *
     * @return {@code Set<String>} of supported parameters
     */
    @Override
    public Set<String> supportedParameters() {
        return SUPPORTED_PARAMETERS;
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
        ExecRuntimeActions action;
        if (sm != null) {
            sm.checkPermission(CredentialStorePermission.LOAD_EXTERNAL_STORE_PASSWORD);
            action = ExecRuntimeActions.PRIVILEGED;
        } else {
            action = ExecRuntimeActions.NON_PRIVILEGED;
        }

        try {
            return createCredentialFromPassword(action.execCmd(cmd));
        } catch (Exception e) {
            throw log.passwordCommandExecutionProblem(
                    log.isInfoEnabled() ? cmd : "not shown", e);
        }
    }


    private interface ExecRuntimeActions {

        ExecRuntimeActions NON_PRIVILEGED = cmd -> {
            Runtime rt = Runtime.getRuntime();
            Process p = rt.exec(cmd);
            InputStream stdin = null;
            String line;
            BufferedReader reader = null;
            try {
                stdin = p.getInputStream();
                reader = new BufferedReader(new InputStreamReader(stdin));
                line = reader.readLine();
            } finally {
                if (reader != null)
                    reader.close();
                if (stdin != null)
                    stdin.close();
            }

            int exitCode = p.waitFor();
            if (log.isTraceEnabled())
                log.tracef("Exit code from password command = %d", Integer.valueOf(exitCode));
            return line != null ? line.toCharArray() : null;
        };

        ExecRuntimeActions PRIVILEGED = cmd -> {
            try {
                return AccessController.doPrivileged((PrivilegedExceptionAction<char[]>) () -> NON_PRIVILEGED.execCmd(cmd));
            } catch (PrivilegedActionException e) {
                throw e.getException();
            }
        };

        char[] execCmd(String cmd) throws Exception;
    }


}
