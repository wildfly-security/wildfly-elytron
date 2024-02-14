/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.util;

import org.jboss.modules.Module;
import org.jboss.modules.ModuleIdentifier;
import org.jboss.modules.ModuleLoadException;

/**
 * Utility class to load a module.
 *
 * JBoss Modules is an optional dependency of Elytron.
 * This class will only be loaded and used when Elytron actually requires the presence of JBoss Modules.

 * @author <a href="http://jmesnil.net/">Jeff Mesnil</a> (c) 2017 Red Hat inc.
 */
public class ModuleLoader {

    /**
     * Returns the class loader of the given module or throws a {@code ConfigXMLParseException} if the module can not be loaded.
     *
     * @param moduleName the name of the module (can not be {@code null}
     * @return the class loader of the module
     * @throws ModuleLoadException if the module can not be loaded
     *
     */
    public static ClassLoader getClassLoaderFromModule(String moduleName) throws ModuleLoadException {
        final ModuleIdentifier identifier = ModuleIdentifier.fromString(moduleName);
        return Module.getModuleFromCallerModuleLoader(identifier).getClassLoader();
    }
}
