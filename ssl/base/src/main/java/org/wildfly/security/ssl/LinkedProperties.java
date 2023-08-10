/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.ssl;

import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * A properties map that is backed by a type-checked linked hash map.  The map can never be made to hold keys
 * or values that are not strings, and will always return entries in the same order they were added.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class LinkedProperties extends Properties {

    private static final long serialVersionUID = 7177745441023482122L;

    private final Map<String, String> realMap;

    LinkedProperties() {
        this(Collections.checkedMap(new LinkedHashMap<String, String>(), String.class, String.class));
    }

    private LinkedProperties(final Map<String, String> realMap) {
        this.realMap = realMap;
    }

    private static <T> T defVal(T val, T def) {
        return val != null ? val : def;
    }

    public String getProperty(final String key) {
        return realMap.get(key);
    }

    public String getProperty(final String key, final String defaultValue) {
        return defVal(realMap.get(key), defaultValue);
    }

    public Object get(final Object key) {
        return realMap.get(key);
    }

    public boolean contains(final Object value) {
        return containsValue(value);
    }

    public boolean containsKey(final Object key) {
        return realMap.containsKey(key);
    }

    @SuppressWarnings("unchecked")
    public Enumeration<Object> keys() {
        return (Enumeration<Object>) Collections.enumeration((Set<?>) realMap.keySet());
    }

    @SuppressWarnings("unchecked")
    public Enumeration<Object> elements() {
        return (Enumeration<Object>) Collections.enumeration((Collection<?>) realMap.values());
    }

    public boolean containsValue(final Object value) {
        return realMap.containsValue(value);
    }

    public Object put(final Object key, final Object value) {
        return realMap.put((String) key, (String) value);
    }

    public Object remove(final Object key) {
        return realMap.remove(key);
    }

    public void clear() {
        realMap.clear();
    }

    @SuppressWarnings("unchecked")
    public Set<Object> keySet() {
        return (Set<Object>) (Set<?>) realMap.keySet();
    }

    @SuppressWarnings("unchecked")
    public Set<Map.Entry<Object, Object>> entrySet() {
        return (Set<Map.Entry<Object, Object>>) (Set<?>) realMap.entrySet();
    }

    @SuppressWarnings("unchecked")
    public Collection<Object> values() {
        return (Collection<Object>) (Collection<?>) realMap.values();
    }

    public Enumeration<?> propertyNames() {
        return Collections.enumeration(realMap.keySet());
    }

    public Set<String> stringPropertyNames() {
        return realMap.keySet();
    }

    public Set<Map.Entry<String, String>> stringMapEntries() {
        return realMap.entrySet();
    }

    public Object setProperty(final String key, final String value) {
        return realMap.put(key, value);
    }

    public int size() {
        return realMap.size();
    }

    public boolean isEmpty() {
        return realMap.isEmpty();
    }

    @SuppressWarnings("CloneDoesntCallSuperClone")
    public LinkedProperties clone() {
        return new LinkedProperties(Collections.checkedMap(new LinkedHashMap<String, String>(realMap), String.class, String.class));
    }
}
