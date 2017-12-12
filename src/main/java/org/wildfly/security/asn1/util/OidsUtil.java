/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.asn1.util;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * OIDs to attribute name and back conversion utility.
 * Use oids.properties file to map each other.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class OidsUtil {

    /**
     * Category of mapping - determine context of the mapping
     */
    public enum Category {
        RDN,
        GSS
    }

    private static Map<Category, Map<String, String>> attributeNameToOidTable = new HashMap<>();
    private static Map<Category, Map<String, String>> oidToAttributeNameTable = new HashMap<>();

    static { // loading OIDs maps from properties file
        for (Category category : Category.values()) {
            attributeNameToOidTable.put(category, new HashMap<>());
            oidToAttributeNameTable.put(category, new HashMap<>());
        }
        try (InputStream stream = OidsUtil.class.getResourceAsStream("oids.properties")) {
            Properties props = new Properties();
            props.load(stream);
            for (String propName : props.stringPropertyNames()) {
                int delimiter = propName.indexOf('.');
                if (delimiter < 0) throw new IllegalStateException();
                Category category = Category.valueOf(propName.substring(0, delimiter));
                String oid = propName.substring(delimiter + 1);
                String[] attributeNames = props.getProperty(propName).split(",");
                for (String attributeName : attributeNames) {
                    attributeNameToOidTable.get(category).put(attributeName, oid);
                }
                oidToAttributeNameTable.get(category).put(oid, attributeNames[0]);
            }
        } catch (Exception e) {
            throw ElytronMessages.log.unableToLoadOidsFromPropertiesFile(e);
        }
    }

    /**
     * Convert an X.500 attribute name (AVA keyword) to OID
     * @param category category of OID / context of the conversion
     * @param attributeName X.500 attribute name
     * @return corresponding OID or {@code null} if was not recognized
     */
    public static String attributeNameToOid(Category category, String attributeName) {
        Assert.checkNotNullParam("category", category);
        Assert.checkNotNullParam("attributeName", attributeName);
        return attributeNameToOidTable.get(category).get(attributeName.toUpperCase(Locale.ROOT));
    }

    /**
     * Convert an X.500 attribute name (AVA keyword) to OID
     * @param category category of OID / context of the conversion
     * @param oid X.500 attribute OID
     * @return corresponding attribute name or {@code null} if was not recognized
     */
    public static String oidToAttributeName(Category category, String oid) {
        Assert.checkNotNullParam("category", category);
        Assert.checkNotNullParam("oid", oid);
        return oidToAttributeNameTable.get(category).get(oid);
    }

}