/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.security.auth.client;

import static org.wildfly.security._private.ElytronMessages.xmlLog;

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
