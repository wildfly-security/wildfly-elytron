/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

/**
 * Utilities for LDAP attributes manipulation.
 *
 * @author <a href="mailto:jondruse@redhat.com">Jiri Ondrusek</a>
 */
public class LdapUtil {

    private static final String BINARY_SUFFIX = ";binary";

    /**
     * Ldap servers can return binary attributes with suffix ;binary. This method helps to solve this case.
     *
     * @param attributes Attributes obtained from server
     * @param name Name of returned attribute
     * @return Attribute with name 'name', 'name;binary' or null if neither of them exists.
     */
    public static Attribute getBinaryAttribute(Attributes attributes, String name) {
        Attribute retVal = attributes.get(name);
        if(retVal == null && !name.endsWith(BINARY_SUFFIX)) {
            retVal = attributes.get(name+BINARY_SUFFIX);
        }
        return retVal;
    }
}
