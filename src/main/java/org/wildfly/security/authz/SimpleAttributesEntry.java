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

package org.wildfly.security.authz;

import java.util.AbstractList;

/**
 * An implementation of {@link Attributes.Entry} which can be used by implementations of {@link Attributes}.  Operations
 * are implemented in terms of methods on {@code Attributes} which do not rely upon entries.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class SimpleAttributesEntry extends AbstractList<String> implements Attributes.Entry {

    private final Attributes attributes;
    private final String key;

    /**
     * Construct a new instance.
     *
     * @param attributes the backing attributes collection
     * @param key the key of this entry
     */
    public SimpleAttributesEntry(final Attributes attributes, final String key) {
        this.attributes = attributes;
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public void removeRange(final int fromIndex, final int toIndex) {
        attributes.removeRange(key, fromIndex, toIndex);
    }

    public String get(final int index) {
        return attributes.get(key, index);
    }

    public String set(final int index, final String element) {
        return attributes.set(key, index, element);
    }

    public void add(final int index, final String element) {
        attributes.add(key, index, element);
    }

    public String remove(final int index) {
        return attributes.remove(key, index);
    }

    public boolean add(final String s) {
        attributes.addLast(key, s);
        return true;
    }

    public void clear() {
        attributes.remove(key);
    }

    public boolean remove(final Object o) {
        return o instanceof String && attributes.removeFirst(key, (String) o);
    }

    public boolean contains(final Object o) {
        return o instanceof String && attributes.containsValue(key, (String) o);
    }

    public boolean isEmpty() {
        return !attributes.containsKey(key);
    }

    public int indexOf(final Object o) {
        return o instanceof String ? attributes.indexOf(key, (String) o) : -1;
    }

    public int lastIndexOf(final Object o) {
        return o instanceof String ? attributes.lastIndexOf(key, (String) o) : -1;
    }

    public int size() {
        return attributes.size(key);
    }
}
