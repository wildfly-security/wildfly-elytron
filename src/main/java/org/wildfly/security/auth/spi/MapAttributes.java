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

package org.wildfly.security.auth.spi;

import java.util.AbstractCollection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.wildfly.common.Assert;

/**
 * A map-backed attributes collection.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class MapAttributes implements Attributes {
    // backing map

    private final Map<String, EntriesList> map;

    // cache fields

    private HashMap<String, Entry> entryCache;
    private Collection<Entry> entries;
    private Collection<String> values;

    /**
     * Construct an instance using a hash map for backing store.
     */
    public MapAttributes() {
        this.map = new HashMap<>();
    }

    /**
     * Construct a new instance copying mappings from an original map.
     *
     * @param original the original map
     */
    public MapAttributes(Map<String, ? extends Collection<String>> original) {
        Assert.checkNotNullParam("original", original);
        Map<String, EntriesList> map = new HashMap<>(original.size());
        for (Map.Entry<String, ? extends Collection<String>> entry : original.entrySet()) {
            map.put(entry.getKey(), new EntriesList(entry.getValue()));
        }
        this.map = map;
    }

    /**
     * Construct a new instance copying mappings from an original attributes collection.
     *
     * @param original the original collection
     */
    public MapAttributes(Attributes original) {
        Assert.checkNotNullParam("original", original);
        Map<String, EntriesList> map = new HashMap<>(original.size());
        for (Entry entry : original.entries()) {
            final EntriesList entriesList = new EntriesList(entry);
            if (! entriesList.isEmpty()) map.put(entry.getKey(), entriesList);
        }
        this.map = map;
    }

    public Set<String> keySet() {
        return map.keySet();
    }

    public Collection<String> values() {
        final Collection<String> values = this.values;
        if (values != null) {
            return values;
        }
        return this.values = Attributes.super.values();
    }

    public Collection<Entry> entries() {
        final Collection<Entry> entries = this.entries;
        if (entries != null) {
            return entries;
        }
        return this.entries = new AbstractCollection<Entry>() {
            public Iterator<Entry> iterator() {
                final Iterator<String> iterator = map.keySet().iterator();
                return new Iterator<Entry>() {

                    public boolean hasNext() {
                        return iterator.hasNext();
                    }

                    public Entry next() {
                        return get(iterator.next());
                    }

                    public void remove() {
                        iterator.remove();
                    }
                };
            }

            public int size() {
                return MapAttributes.this.size();
            }
        };
    }

    public int size(final String key) {
        final EntriesList list = map.get(key);
        return list == null ? 0 : list.size();
    }

    public boolean remove(final String key) {
        return map.remove(key) != null;
    }

    public void add(final String key, final int idx, final String value) {
        EntriesList list = map.get(key);
        if (list == null) {
            map.put(key, list = new EntriesList());
        }
        list.add(idx, value);
    }

    public String get(final String key, final int idx) {
        EntriesList list = map.get(key);
        return list == null ? null : list.get(idx);
    }

    public String set(final String key, final int idx, final String value) {
        EntriesList list = map.get(key);
        if (list == null) {
            throw new IndexOutOfBoundsException();
        }
        return list.set(idx, value);
    }

    public String remove(final String key, final int idx) {
        EntriesList list = map.get(key);
        if (list == null) {
            throw new IndexOutOfBoundsException();
        }
        final String result = list.remove(idx);
        if (list.isEmpty()) {
            map.remove(key);
        }
        return result;
    }

    public List<String> copyAndRemove(final String key) {
        final EntriesList old = map.remove(key);
        return old == null ? new ArrayList<>(0) : old;
    }

    public List<String> copyAndReplace(final String key, final Collection<String> values) {
        final EntriesList old = map.replace(key, new EntriesList(values));
        return old == null ? new ArrayList<>(0) : old;
    }

    public boolean containsKey(final String key) {
        return map.containsKey(key);
    }

    public boolean containsValue(final String key, final String value) {
        final EntriesList list = map.get(key);
        return list != null && list.contains(value);
    }

    public void removeRange(final String key, final int from, final int to) {
        final EntriesList list = map.get(key);
        if (list == null) {
            throw new IndexOutOfBoundsException();
        }
        list.removeRange(from, to);
    }

    public int indexOf(final String key, final String value) {
        EntriesList list = map.get(key);
        return list == null ? -1 : list.indexOf(value);
    }

    public int lastIndexOf(final String key, final String value) {
        EntriesList list = map.get(key);
        return list == null ? -1 : list.lastIndexOf(value);
    }

    public boolean set(final String key, final int idx, final String expect, final String update) {
        EntriesList list = map.get(key);
        if (list == null || !list.get(idx).equals(expect)) {
            return false;
        }
        list.set(idx, update);
        return true;
    }

    public String getFirst(final String key) {
        EntriesList list = map.get(key);
        return list == null ? null : list.get(0);
    }

    public String getLast(final String key) {
        EntriesList list = map.get(key);
        return list == null ? null : list.get(list.size() - 1);
    }

    public void addFirst(final String key, final String value) {
        EntriesList list = map.get(key);
        if (list == null) {
            map.put(key, list = new EntriesList());
        }
        list.add(0, value);
    }

    public void addLast(final String key, final String value) {
        EntriesList list = map.get(key);
        if (list == null) {
            map.put(key, list = new EntriesList());
        }
        list.add(value);
    }

    public boolean removeFirst(final String key, final String value) {
        EntriesList list = map.get(key);
        if (list == null) {
            return false;
        }
        int idx = list.indexOf(value);
        if (idx == -1) {
            return false;
        }
        list.remove(idx);
        if (list.isEmpty()) {
            map.remove(key);
        }
        return true;
    }

    public boolean removeLast(final String key, final String value) {
        EntriesList list = map.get(key);
        if (list == null) {
            return false;
        }
        int idx = list.lastIndexOf(value);
        if (idx == -1) {
            return false;
        }
        list.remove(idx);
        if (list.isEmpty()) {
            map.remove(key);
        }
        return true;
    }

    public String removeFirst(final String key) {
        EntriesList list = map.get(key);
        if (list == null) {
            return null;
        }
        final String removed = list.remove(0);
        if (list.isEmpty()) {
            map.remove(key);
        }
        return removed;
    }

    public String removeLast(final String key) {
        EntriesList list = map.get(key);
        if (list == null) {
            return null;
        }
        final String removed = list.remove(list.size() - 1);
        if (list.isEmpty()) {
            map.remove(key);
        }
        return removed;
    }

    public boolean remove(final String key, final int idx, final String value) {
        EntriesList list = map.get(key);
        if (list == null) {
            return false;
        }
        if (! list.get(idx).equals(value)) {
            return false;
        }
        list.remove(idx);
        if (list.isEmpty()) {
            map.remove(key);
        }
        return true;
    }

    public boolean removeAll(final String key, final String value) {
        EntriesList list = map.get(key);
        return list != null && list.removeAll(Collections.singleton(value));
    }

    public Entry get(final String key) {
        HashMap<String, Entry> entryCache = this.entryCache;
        if (entryCache == null) {
            entryCache = this.entryCache = new HashMap<>();
        }
        return entryCache.computeIfAbsent(key, s -> new SimpleAttributesEntry(this, s));
    }

    public int size() {
        return map.size();
    }

    public boolean isEmpty() {
        return map.isEmpty();
    }

    public void clear() {
        map.clear();
    }

    static final class EntriesList extends ArrayList<String> implements Set<String> {

        private static final long serialVersionUID = 8113580421577650775L;

        EntriesList(final int initialCapacity) {
            super(initialCapacity);
        }

        EntriesList() {
        }

        EntriesList(final Collection<? extends String> c) {
            super(c);
        }

        public void removeRange(final int fromIndex, final int toIndex) {
            super.removeRange(fromIndex, toIndex);
        }
    }
}
