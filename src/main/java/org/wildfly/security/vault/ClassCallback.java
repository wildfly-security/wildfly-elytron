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
package org.wildfly.security.vault;

import java.util.Map;

/**
 * Callback to obtain password from external source based on class.
 *
 * The class has to implement {@link PasswordClass} interface.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public final class ClassCallback extends VaultPasswordCallback {

    private final String className;
    private final String module;

    private final Map<String, ?> parameters;
    private final Object[] arguments;

    /**
     * Creates {@code ClassCallback} instance from {@code className} loaded from {@code module} using its default constructor.
     *
     * @param className of the password class to use to resolve password
     * @param module name of module to load password class from. Can be null.
     */
    public ClassCallback(final String className, final String module) {
        this(className, module, null, null);
    }

    /**
     * Creates {@code ClassCallback} instance from {@code className} loaded from {@code module} using its constructor with signature of {@code Map<String, ?>} or {@code Object[]}.
     *
     * @param className of the password class to use to resolve password
     * @param module name of module to load password class from. Can be null.
     * @param parameters {@code Map<String, ?>} of parameters to pass to password class' constructor. Can be null.
     * @param arguments array of arguments to pass to class' constructor. Can be null.
     */
    public ClassCallback(final String className, final String module, final Map<String, ?> parameters, final Object[] arguments) {
        this.className = className;
        this.module = module;
        this.parameters = parameters;
        this.arguments = arguments;
    }

    /**
     *
     * @return className value
     */
    public String getClassName() {
        return className;
    }

    /**
     *
     * @return module name value
     */
    public String getModule() {
        return module;
    }

    /**
     *
     * @return parameters passed in
     */
    public Map<String, ?> getParameters() {
        return parameters;
    }

    /**
     *
     * @return arguments passed in
     */
    public Object[] getArguments() {
        return arguments;
    }
}
