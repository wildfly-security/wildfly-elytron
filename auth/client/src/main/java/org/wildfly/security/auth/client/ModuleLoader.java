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

package org.wildfly.security.auth.client;

import static org.wildfly.security.auth.client._private.ElytronMessages.xmlLog;

import javax.xml.stream.XMLStreamReader;

import org.jboss.logging.annotations.Param;
import org.jboss.modules.Module;
import org.jboss.modules.ModuleIdentifier;
import org.jboss.modules.ModuleLoadException;
import org.wildfly.client.config.ConfigXMLParseException;

/**
 * Utility class to load a module.
 *
 * JBoss Modules is an optional dependency of Elytron.
 * This class will only be loaded and used when Elytron actually requires the presence of JBoss Modules.

 * @author <a href="http://jmesnil.net/">Jeff Mesnil</a> (c) 2017 Red Hat inc.
 */
class ModuleLoader {

    /**
     * Returns the class loader of the given module or throws a {@code ConfigXMLParseException} if the module can not be loaded.
     *
     * @param moduleName the name of the module (can not be {@code null}
     * @return the class loader of the module
     * @throws ConfigXMLParseException if the module can not be loaded
     *
     */
    static ClassLoader getClassLoaderFromModule(@Param XMLStreamReader reader, String moduleName) throws ConfigXMLParseException {
        final ModuleIdentifier identifier = ModuleIdentifier.fromString(moduleName);
        try {
            return Module.getModuleFromCallerModuleLoader(identifier).getClassLoader();
        } catch (ModuleLoadException e) {
            throw xmlLog.xmlNoModuleFound(reader, e, identifier.toString());
        }
    }
}
