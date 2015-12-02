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
package org.wildfly.security.credential.store.external;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jboss.modules.Module;
import org.jboss.modules.ModuleIdentifier;
import org.jboss.modules.ModuleLoader;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStorePermission;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * A {@link CallbackHandler} supporting following {@link Callback}s.
 *
 * {@link ExtCallback} - external command execution using space separated parameters
 * {@link CmdCallback} - external command execution using comma separated parameters ({@link ProcessBuilder} style)
 * {@link ClassCallback} - password loaded from a {@code class} from custom {@link Module} implementing {@link PasswordClass} interface
 * {@link MaskedPasswordCallback} - callback for obtaining PBE encrypted password compatible with legacy {@code PicketBox} PBE style encryption
 * {@link ParametrizedCallback} - interface for custom callbacks
 * {@link PasswordCallback} - old good callback from {@code javax.security.auth.callback}
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public final class CredentialStoreCallbackHandler implements CallbackHandler {

    /**
     * Default constructor.
     */
    public CredentialStoreCallbackHandler() {}

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(CredentialStorePermission.LOAD_EXTERNAL_STORE_PASSWORD);
        }

        for (Callback callback: callbacks) {
            if (callback instanceof ExtCallback) {
                ExtCallback extCallback = (ExtCallback)callback;
                try {
                    if (sm != null) {
                        extCallback.setPassword(
                                createCredentialFromPassword(ExecRuntimeActions.PRIVILEGED.execCmd(extCallback.getArgLine())));
                    } else {
                        extCallback.setPassword(
                                createCredentialFromPassword(ExecRuntimeActions.NON_PRIVILEGED.execCmd(extCallback.getArgLine())));
                    }
                } catch (Exception e) {
                    throw new IOException(e);
                }
            } else if (callback instanceof CmdCallback) {
                CmdCallback cmdCallback = (CmdCallback)callback;
                try {
                    if (sm != null) {
                        cmdCallback.setPassword(
                                createCredentialFromPassword(CmdRuntimeActions.PRIVILEGED.execCmd(cmdCallback.getArgs())));
                    } else {
                        cmdCallback.setPassword(
                                createCredentialFromPassword(CmdRuntimeActions.NON_PRIVILEGED.execCmd(cmdCallback.getArgs())));
                    }
                } catch (Exception e) {
                    throw new IOException(e);
                }
            } else if (callback instanceof ClassCallback) {
                ClassCallback classCallback = (ClassCallback) callback;
                try {
                    classCallback.setPassword(createCredentialFromPassword(invokePasswordClass(
                            new ClassModuleSpec(classCallback.getClassName(), classCallback.getModule()), classCallback.getParameters(), classCallback.getArguments())));
                } catch (Exception e) {
                    throw new IOException(e);
                }
            } else if (callback instanceof MaskedPasswordCallback) {
                MaskedPasswordCallback maskedPasswordCallback = (MaskedPasswordCallback) callback;
                try {
                    maskedPasswordCallback.setPassword(
                            createCredentialFromPassword(
                                    MaskedPasswordDecoder.decode(
                                            maskedPasswordCallback.getMaskedPasswordString(),
                                            maskedPasswordCallback.getSalt(),
                                            maskedPasswordCallback.getIterationCount(),
                                            maskedPasswordCallback.getPBEAlgorithm(),
                                            maskedPasswordCallback.getInitialKeyMaterial())));
                } catch (Exception e) {
                    throw new IOException(e);
                }
            } else if (callback instanceof PasswordCallback) {
                // do nothing as password is already set and we don't want to throw UnsupportedCallbackException
            } else if (callback instanceof ParametrizedCallback<?>) {
                // do nothing as password is already set and we don't want to throw UnsupportedCallbackException
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }

    }

    private Credential createCredentialFromPassword(char[] password) throws UnsupportedCredentialTypeException {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
            return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedCredentialTypeException(e);
        }
    }

    private interface ExecRuntimeActions {
        ExecRuntimeActions PRIVILEGED = new ExecRuntimeActions() {
            public char[] execCmd(final String cmd) throws Exception {
                try {
                    char[] line = AccessController.doPrivileged(new PrivilegedExceptionAction<char[]>() {
                        public char[] run() throws Exception {
                            return NON_PRIVILEGED.execCmd(cmd);
                        }
                    });
                    return line;
                } catch (PrivilegedActionException e) {
                    throw e.getException();
                }
            }
        };
        ExecRuntimeActions NON_PRIVILEGED = new ExecRuntimeActions() {
            public char[] execCmd(final String cmd) throws Exception {
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
            }
        };

        char[] execCmd(String cmd) throws Exception;
    }

    private interface CmdRuntimeActions {
        CmdRuntimeActions PRIVILEGED = new CmdRuntimeActions() {
            public char[] execCmd(final String[] parsedCommand) throws Exception {
                try {
                    char[] password = AccessController.doPrivileged(new PrivilegedExceptionAction<char[]>() {
                        public char[] run() throws Exception {
                            return NON_PRIVILEGED.execCmd(parsedCommand);
                        }
                    });
                    return password;
                } catch (PrivilegedActionException e) {
                    throw e.getException();
                }
            }
        };
        CmdRuntimeActions NON_PRIVILEGED = new CmdRuntimeActions() {
            public char[] execCmd(final String[] parsedCommand) throws Exception {
                final ProcessBuilder builder = new ProcessBuilder(parsedCommand);
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

        char[] execCmd(String[] parsedCommand) throws Exception;
    }

    private static char[] invokePasswordClass(final ClassModuleSpec passwordClassSpec, final Map<String, ?> passwordClassParameters, final Object[] passwordClassArguments) throws ExternalCredentialException {

        Class<?> c;
        try {
            c = loadPasswordClass(passwordClassSpec);
        } catch (Exception e) {
            throw new ExternalCredentialException(e);
        }

        Object instance = null;
        try {
            if (passwordClassParameters != null && passwordClassParameters.size() > 0) {
                Class<?>[] sig = {Map.class};
                try {
                    Constructor<?> ctor = c.getConstructor(sig);
                    instance = ctor.newInstance(passwordClassParameters);
                } catch (NoSuchMethodException e) {
                    throw log.passwordClassProblem(e);
                }
            } else if (passwordClassArguments != null && passwordClassArguments.length > 0) {
                Class<?>[] sig = null;
                sig = new Class[passwordClassArguments.length];
                for (int i = 0; i < passwordClassArguments.length; i++) {
                    sig[i] = passwordClassArguments[i].getClass();
                }
                try {
                    Constructor<?> ctor = c.getConstructor(sig);
                    instance = ctor.newInstance(passwordClassArguments);
                } catch (NoSuchMethodException e) {
                    throw log.passwordClassProblem(e);
                }
            } else {
                // Use the default constructor
                instance = c.newInstance();
            }
        } catch (InvocationTargetException | InstantiationException | IllegalAccessException e) {
            throw log.passwordClassProblem(e);
        }

        if (!(instance instanceof PasswordClass)) {
            throw log.wrongPasswordClass(PasswordClass.class.getName());
        }

        char[] password;
        try {
            PasswordClass passwordClass = (PasswordClass)instance;
            password = passwordClass.getPassword();
            passwordClass.destroy();
        } catch (Throwable e) {
            throw new ExternalCredentialException(e);
        }
        return password != null ? password.clone() : null;
    }

    private static Class<?> loadPasswordClass(final ClassModuleSpec passwordClassSpec) throws Exception {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Class<?>>() {
                @Override
                public Class<?> run() throws Exception {
                    if (passwordClassSpec.getClassName() == null || passwordClassSpec.getClassName().isEmpty()) {
                        throw log.passwordClassNotSpecified();
                    } else if (passwordClassSpec.getModule() == null) {
                        ClassLoader cl = Thread.currentThread().getContextClassLoader();
                        return cl.loadClass(passwordClassSpec.getClassName());
                    } else {
                        ModuleLoader loader = Module.getCallerModuleLoader();
                        final Module pwdClassModule = loader.loadModule(ModuleIdentifier.fromString(passwordClassSpec.getModule()));
                        return pwdClassModule.getClassLoader().loadClass(passwordClassSpec.getClassName());
                    }
                }
            });
        } catch (PrivilegedActionException e) {
            throw e.getException();
        }
    }

}
