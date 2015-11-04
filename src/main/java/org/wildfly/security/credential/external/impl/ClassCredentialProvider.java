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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import org.jboss.modules.Module;
import org.jboss.modules.ModuleIdentifier;
import org.jboss.modules.ModuleLoader;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.external.ExternalCredentialException;
import org.wildfly.security.credential.external.PasswordClass;
import org.wildfly.security.credential.store.CredentialStorePermission;

/**
 * {@link org.wildfly.security.credential.external.ExternalCredentialSpi} implementation which supports getting
 * credentials from {@link PasswordClass}.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class ClassCredentialProvider extends ExternalCredentialProvider {

    /**
     * Parameter name which denotes class name
     */
    public static final String CLASS_NAME = "className";
    /**
     * Parameter name which denotes module name (JBoss Modules)
     */
    public static final String MODULE = "module";

    /**
     * Separator character between 'CLASS' and module
     */
    public static final String SEPARATOR = "@";

    static final Set<String> SUPPORTED_PARAMETERS = Collections.unmodifiableSet(new HashSet<>(
            Arrays.asList(CLASS_NAME, MODULE)));
    private static final String[] EMPTY_ARGUMENTS = new String[]{};

    @Override
    public <C extends Credential> C resolveCredential(Map<String, String> parameters, Class<C> credentialType)
            throws ExternalCredentialException {
        try {
            return credentialType.cast(createCredentialFromPassword(
                    invokePasswordClass(new ClassModuleSpec(parameters.get(CLASS_NAME), parameters.get(MODULE)),
                            parameters, null)));
        } catch (Exception e) {
            throw new ExternalCredentialException(e);
        }
    }

    @Override
    public <C extends Credential> C resolveCredential(String passwordCommand, Class<C> credentialType)
            throws ExternalCredentialException {

        String passwordCmdType = null;
        String passwordCmdLine = null;

        // Look for a {...} prefix indicating a password command
        if (passwordCommand.startsWith("{CLASS")) {
            StringTokenizer tokenizer = new StringTokenizer(passwordCommand, "{}");
            passwordCmdType = tokenizer.nextToken();
            passwordCmdLine = tokenizer.nextToken();
        } else {
            throw log.passwordClassNotSpecified();
        }

        String module = null;
        if (passwordCmdType.contains(SEPARATOR)) {
            module = passwordCmdType.split(SEPARATOR)[1];
        }
        // Check for a ctor argument delimited by ':'
        String className;
        String constructorArguments = null;
        String[] arguments;
        int colon = passwordCmdLine.indexOf(':');
        if (colon > 0) {
            className = passwordCmdLine.substring(0, colon);
            constructorArguments = passwordCmdLine.substring(colon + 1);
            arguments = constructorArguments.split(",", 100);
        } else {
            className = passwordCmdLine;
            arguments = EMPTY_ARGUMENTS;
        }

        try {
            return credentialType.cast(createCredentialFromPassword(
                    invokePasswordClass(new ClassModuleSpec(className, module),
                            null, arguments)));
        } catch (Exception e) {
            throw new ExternalCredentialException(e);
        }
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


    private static char[] invokePasswordClass(final ClassModuleSpec passwordClassSpec, final Map<String, String> passwordClassParameters, final Object[] passwordClassArguments)
            throws ExternalCredentialException {

        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(CredentialStorePermission.LOAD_EXTERNAL_STORE_PASSWORD);
        }

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
            return AccessController.doPrivileged((PrivilegedExceptionAction<Class<?>>) () -> {
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
            });
        } catch (PrivilegedActionException e) {
            throw e.getException();
        }
    }

}
