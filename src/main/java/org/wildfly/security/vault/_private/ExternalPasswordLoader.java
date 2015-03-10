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
package org.wildfly.security.vault._private;

import org.jboss.modules.Module;
import org.jboss.modules.ModuleIdentifier;
import org.jboss.modules.ModuleLoadException;
import org.wildfly.security.vault.CallbackShortName;
import org.wildfly.security.vault.ClassCallback;
import org.wildfly.security.vault.CmdCallback;
import org.wildfly.security.vault.ExtCallback;
import org.wildfly.security.vault.MaskedPasswordCallback;
import org.wildfly.security.vault.ParametrizedCallback;
import org.wildfly.security.vault.ParametrizedCallbackHandler;
import org.wildfly.security.vault.VaultCallbackHandler;
import org.wildfly.security.vault.VaultException;
import org.wildfly.security.vault.VaultPasswordCallback;
import org.wildfly.security.vault.VaultSpi;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.security.PrivilegedAction;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.security.AccessController.doPrivileged;
import static org.wildfly.security._private.ElytronMessages.log;
/**
 * Class for handling all forms of external password loading to be used with {@link ElytronVault}
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
class ExternalPasswordLoader {

    private String callbackOptionName;
    private String callbackHandlerOptionName;
    private String passwordClassOptionName = VaultSpi.CALLBACK_PASSWORD_CLASS;
    private String clearTextPasswordOptionName = VaultSpi.STORAGE_PASSWORD;
    private String maskedPasswordOptionName;
    private String saltOptionName;
    private String iterationOptionName;
    private String PBEAlgorithmOptionName;
    private String PBEInitialKeyOptionName;

    static final String[] EMPTY_STRINGS = new String[]{};

    ExternalPasswordLoader(final String callbackOptionName, final String callbackHandlerOptionName,
                           final String passwordClassOptionName, final String clearTextPasswordOptionName,
                           final String maskedPasswordOptionName, final String saltOptionName, final String iterationOptionName, final String PBEAlgorithmOptionName, final String PBEInitialKeyOptionName) {
        this.callbackOptionName = callbackOptionName;
        this.callbackHandlerOptionName = callbackHandlerOptionName;
        this.passwordClassOptionName = passwordClassOptionName;
        this.clearTextPasswordOptionName = clearTextPasswordOptionName;
        this.maskedPasswordOptionName = maskedPasswordOptionName;
        this.saltOptionName = saltOptionName;
        this.iterationOptionName = iterationOptionName;
        this.PBEAlgorithmOptionName = PBEAlgorithmOptionName;
        this.PBEInitialKeyOptionName = PBEInitialKeyOptionName;
    }

    ExternalPasswordLoader() {
        this(VaultSpi.CALLBACK, VaultSpi.CALLBACK_HANDLER,
                VaultSpi.CALLBACK_PASSWORD_CLASS, VaultSpi.STORAGE_PASSWORD,
                VaultSpi.CALLBACK_MASKED, VaultSpi.CALLBACK_SALT, VaultSpi.CALLBACK_ITERATION, VaultSpi.CALLBACK_PBE_ALGORITHM, VaultSpi.CALLBACK_PBE_INITIAL_KEY);
    }

    char[] loadPassword(final Map<String, Object> options) throws VaultException, IllegalAccessException, InstantiationException, IOException, UnsupportedCallbackException, NoSuchMethodException {
        CallbackHandler cbh = null;
        if (options.get(callbackHandlerOptionName) != null) {
            String callbackHandlerSpec = (String)options.get(callbackHandlerOptionName);

            Class<?> callbackHandlerClass = loadClass(callbackHandlerSpec);
            cbh = (CallbackHandler) callbackHandlerClass.newInstance();

            if (ParametrizedCallbackHandler.class.isInstance(cbh)) {
                ((ParametrizedCallbackHandler) cbh).initialize(options2Arguments(options, callbackHandlerOptionName));
            }
        } else {
            cbh = new VaultCallbackHandler();
        }

        Callback[] callbacks = null;
        if (options.get(callbackOptionName) != null) {
            String callbackSpec = resolveShortName((String) options.get(callbackOptionName));
            if (callbackSpec.equals(CallbackShortName.EXT.get())) {
                String[] args = options2Arguments(options, callbackOptionName);
                if (args.length == 1) {
                    ExtCallback extCb = new ExtCallback(args[0]);
                    callbacks = new Callback[] {extCb};
                } else {
                    throw log.extCallbackWrongParameterCount();
                }
            } else if (callbackSpec.equals(CallbackShortName.CMD.get())) {
                String[] args = options2Arguments(options, callbackOptionName);
                if (args.length >= 1) {
                    CmdCallback cmdCb = (args.length == 1 ? new CmdCallback(args[0]) : new CmdCallback(args));
                    callbacks = new Callback[] {cmdCb};
                } else {
                    throw log.cmdCallbackWrongParameterCount();
                }
            } else if (callbackSpec.equals(CallbackShortName.CLASS.get())) {
                ClassModuleSpec passwordClassClassModuleSpec = ClassModuleSpec.parse((String)options.get(passwordClassOptionName));
                Map<String, ?> callbackParameters = options.entrySet().stream().filter(entry -> entry.getKey().startsWith(callbackOptionName))
                        .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()));
                ClassCallback classCb = new ClassCallback(passwordClassClassModuleSpec.getClassName(), passwordClassClassModuleSpec.getModule(), callbackParameters, null);
                callbacks = new Callback[] {classCb};
            } else if (callbackSpec.equals(CallbackShortName.MASKED.get())) {
                MaskedPasswordCallback maskedPasswordCallback = new MaskedPasswordCallback(
                        (String)options.get(maskedPasswordOptionName),
                        (String)options.get(saltOptionName),
                        Integer.parseInt((String)options.get(iterationOptionName)),
                        (String)options.get(PBEAlgorithmOptionName),
                        (String)options.get(PBEInitialKeyOptionName));
                callbacks = new Callback[] {maskedPasswordCallback};
            } else {
                Class<?> callbackClass = loadClass(callbackSpec);
                if (ParametrizedCallback.class.isAssignableFrom(callbackClass)) {
                    Map<String, ?> callbackParameters = options.entrySet().stream().filter(entry -> entry.getKey().startsWith(callbackOptionName))
                            .collect(Collectors.toMap(e -> e.getKey(), e->e.getValue()));
                    ParametrizedCallback pCb = (ParametrizedCallback)callbackClass.newInstance();
                    pCb.initialize(callbackParameters);
                    callbacks = new Callback[] {pCb};
                } else if (Callback.class.isAssignableFrom(callbackClass)) {
                    Callback cb = (Callback) callbackClass.newInstance();
                    callbacks = new Callback[] {cb};
                } else {
                    throw log.callbackNotSupported(callbackSpec);
                }
            }
        } else {
            Callback cb = null;
            Object pass = options.get(clearTextPasswordOptionName);
            if (pass != null && pass instanceof char[]) {
                PasswordCallback pcb = new PasswordCallback("Password", false);
                pcb.setPassword((char[])pass);
                cb = pcb;
            } else if (pass != null && pass instanceof String) {
                String passSpec = (String) pass;
                if (passSpec.startsWith("{")) {
                    cb = PasswordLoaderBridge.createCallback(passSpec, options);
                } else {
                    PasswordCallback pcb = new PasswordCallback("Password", false);
                    pcb.setPassword(passSpec.toCharArray());
                    cb = pcb;
                }
            }
            callbacks = new Callback[] {cb};
        }

        cbh.handle(callbacks);

        if (callbacks[0] instanceof VaultPasswordCallback) {
            char[] password = ((VaultPasswordCallback)callbacks[0]).getPassword();
            try {
                ((VaultPasswordCallback) callbacks[0]).destroy();
            } catch (DestroyFailedException e) {
                throw new VaultException(e);
            }
            return password;
        } else if (callbacks[0] instanceof ParametrizedCallback) {
            char[] password = ((ParametrizedCallback)callbacks[0]).getPassword();
            try {
                ((ParametrizedCallback) callbacks[0]).destroy();
            } catch (DestroyFailedException e) {
                throw new VaultException(e);
            }
            return password;

        } else if (callbacks[0] instanceof PasswordCallback) {
            char[] password = ((PasswordCallback)callbacks[0]).getPassword();
            ((PasswordCallback)callbacks[0]).clearPassword();
            return password;
        }
        return null;
    }

    private String resolveShortName(final String classSpec) {
        for (CallbackShortName sn: CallbackShortName.values()) {
            if (sn.name().equalsIgnoreCase(classSpec)) {
                return sn.get();
            }
        }
        return classSpec;
    }

    private Class<?> loadClass(final String classSpec) {
        if (classSpec != null) {
            final ClassModuleSpec classModuleSpec = ClassModuleSpec.parse(classSpec);
            return doPrivileged(new PrivilegedAction<Class<?>>() {
                @Override
                public Class<?> run() {
                    try {
                        if (classModuleSpec.getModule() != null) {
                            return Module.loadClassFromCallerModuleLoader(ModuleIdentifier.fromString(classModuleSpec.getModule()), classModuleSpec.getClassName());
                        } else {
                            return getClass().getClassLoader().loadClass(classModuleSpec.getClassName());
                        }
                    } catch (ModuleLoadException | ClassNotFoundException e) {
                        throw log.vaultRuntimeException(e);
                    }
                }
            });
        } else {
            return VaultCallbackHandler.class;
        }
    }

    static String[] options2Arguments(final Map<String, Object> options, String key) {
        List<String> keyList = options.entrySet().stream().map(Map.Entry<String, Object>::getKey).filter(s -> s.startsWith(key))
                .sorted().skip(1).collect(Collectors.toList());
        String[] arguments;
        if (keyList.size() > 0) {
            arguments = new String[keyList.size()];
            int i = 0;
            for (String k : keyList) {
                arguments[i++] = (String) options.get(k);
            }
        } else {
            arguments = EMPTY_STRINGS;
        }
        return arguments;
    }
}