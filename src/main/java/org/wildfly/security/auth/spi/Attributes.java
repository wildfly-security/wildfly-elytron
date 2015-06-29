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
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;

import org.wildfly.common.Assert;

/**
 * A collection of string attributes.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface Attributes {

    /**
     * Empty, read-only attribute collection.
     */
    Attributes EMPTY = new Attributes() {
        public Collection<Entry> entries() {
            return Collections.emptySet();
        }

        public int size(final String key) {
            return 0;
        }

        public boolean remove(final String key) {
            return false;
        }

        public void add(final String key, final int idx, final String value) {
            throw Assert.unsupported();
        }

        public String get(final String key, final int idx) {
            return null;
        }

        public String set(final String key, final int idx, final String value) {
            throw Assert.unsupported();
        }

        public String remove(final String key, final int idx) {
            throw Assert.unsupported();
        }

        public Entry get(final String key) {
            return new SimpleAttributesEntry(this, key);
        }

        public int size() {
            return 0;
        }

        public void clear() {
        }
    };

    /**
     * Get the entry collection.  Changes to the entry collection will modify this attribute collection, if it is
     * writable.  The returned entries will remain up to date with the state of this collection.
     *
     * @return the entry collection
     */
    Collection<Entry> entries();

    /**
     * Get the number of values mapped to the given key.
     *
     * @param key the key
     * @return the number of mapped values
     */
    int size(String key);

    /**
     * Remove all values for the given key from this collection.
     *
     * @param key the key
     * @return {@code true} if the key was found, {@code false} otherwise
     */
    boolean remove(String key);

    /**
     * Add a mapping for the given key at the given position.
     *
     * @param key the key
     * @param idx the index
     * @param value the mapping value
     * @throws IndexOutOfBoundsException if {@code idx} is less than 0 or greater than or equal to {@code size(key)}
     */
    void add(String key, int idx, String value);

    /**
     * Get the mapping for the given key at the given position.
     *
     * @param key the key
     * @param idx the index
     * @return the mapping value
     * @throws IndexOutOfBoundsException if {@code idx} is less than 0 or greater than or equal to {@code size(key)}
     */
    String get(String key, int idx);

    /**
     * Modify the mapping for the given key at the given position.
     *
     * @param key the key
     * @param idx the index
     * @param value the mapping value
     * @return the previous mapping value
     * @throws IndexOutOfBoundsException if {@code idx} is less than 0 or greater than or equal to {@code size(key)}
     */
    String set(String key, int idx, String value);

    /**
     * Remove and return the mapping for the given key at the given position.  All later entries for that key are shifted
     * up to fill in the gap left by the removed element.
     *
     * @param key the key
     * @param idx the index
     * @return the previous mapping value
     * @throws IndexOutOfBoundsException if {@code idx} is less than 0 or greater than or equal to {@code size(key)}
     */
    String remove(String key, int idx);

    /**
     * Get the number of keys in this attribute collection.
     *
     * @return the number of keys
     */
    int size();

    /**
     * Clear this collection, resetting its size to zero.
     */
    void clear();

    /**
     * Remove all values for the given key from this collection, copying the values into a list which is returned.
     *
     * @param key the key
     * @return the values as a list (not {@code null})
     */
    default List<String> copyAndRemove(String key) {
        final Entry values = get(key);
        List<String> copy = values.isEmpty() ? Collections.emptyList() : new ArrayList<>(values);
        remove(key);
        return copy;
    }

    /**
     * Get all the values of all the keys in this collection.  The returned collection can be used to modify this
     * attributes collection.
     *
     * @return the collection of all values (not {@code null})
     */
    default Collection<String> values() {
        return new AbstractCollection<String>() {
            public Iterator<String> iterator() {
                final Iterator<Entry> entries = entries().iterator();
                return new Iterator<String>() {
                    private Iterator<String> values;

                    public boolean hasNext() {
                        for (;;) {
                            if (values == null) {
                                if (! entries.hasNext()) {
                                    return false;
                                }
                                values = entries.next().iterator();
                            } else if (values.hasNext()) {
                                return true;
                            } else {
                                values = null;
                            }
                        }
                    }

                    public String next() {
                        if (! hasNext()) throw new NoSuchElementException();
                        return values.next();
                    }

                    public void remove() {
                        final Iterator<String> values = this.values;
                        if (values == null) {
                            throw new IllegalStateException();
                        }
                        values.remove();
                    }
                };
            }

            public void clear() {
                Attributes.this.clear();
            }

            public boolean removeAll(final Collection<?> c) {
                boolean changed = false;
                for (Entry entries : entries()) {
                    changed = entries.removeAll(c) || changed;
                }
                return changed;
            }

            public boolean retainAll(final Collection<?> c) {
                boolean changed = false;
                for (Entry entries : entries()) {
                    changed = entries.retainAll(c) || changed;
                }
                return changed;
            }

            public boolean isEmpty() {
                for (Entry entries : entries()) {
                    if (! entries.isEmpty()) {
                        return false;
                    }
                }
                return true;
            }

            public int size() {
                int size = 0;
                for (Entry entries : entries()) {
                    size += entries.size();
                }
                return size;
            }
        };
    }

    /**
     * Get a set comprised of all the keys in this collection.  The returned set can be used to modify this attributes
     * collection.
     *
     * @return the set of all keys (not {@code null})
     */
    default Set<String> keySet() {
        return new AbstractSet<String>() {
            public Iterator<String> iterator() {
                final Iterator<Entry> entries = entries().iterator();
                return new Iterator<String>() {
                    public boolean hasNext() {
                        return entries.hasNext();
                    }

                    public String next() {
                        return entries.next().getKey();
                    }

                    public void remove() {
                        entries.remove();
                    }
                };
            }

            public boolean contains(final Object o) {
                return o instanceof String && Attributes.this.containsKey((String) o);
            }

            public boolean remove(final Object o) {
                return o instanceof String && Attributes.this.remove((String) o);
            }

            public void clear() {
                Attributes.this.clear();
            }

            public int size() {
                return Attributes.this.size();
            }
        };
    }

    /**
     * Conditionally set a specific value of a given key to a new value, if the existing value matches the {@code expect}
     * parameter.
     *
     * @param key the key
     * @param idx the index
     * @param expect the expected value
     * @param update the value to set
     * @return {@code true} if the actual value matched the expected value and was updated, {@code false} otherwise
     * @throws IndexOutOfBoundsException if {@code idx} is less than 0 or greater than or equal to {@code size(key)}
     */
    default boolean set(String key, int idx, String expect, String update) {
        Assert.checkNotNullParam("update", update);
        if (expect == null || idx < 0 || idx >= size(key) || ! get(key, idx).equals(expect)) {
            return false;
        }
        set(key, idx, update);
        return true;
    }

    /**
     * Get the index of the first occurrence of the given value at the given key, if any.
     *
     * @param key the key
     * @param value the value
     * @return the index, or -1 if the value was not found at the given key
     */
    default int indexOf(String key, String value) {
        final int size = size(key);
        for (int i = 0; i < size; i ++) {
            if (get(key, i).equals(value)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Get the index of the last occurrence of the given value at the given key, if any.
     *
     * @param key the key
     * @param value the value
     * @return the index, or -1 if the value was not found at the given key
     */
    default int lastIndexOf(String key, String value) {
        final int size = size(key);
        for (int i = size - 1; i >= 0; i --) {
            if (get(key, i).equals(value)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Remove all the values for the given key between the {@code from} index (inclusive) and the {@code to} index
     * (exclusive).
     *
     * @param key the key
     * @param from the start index (inclusive)
     * @param to the end index (exclusive)
     * @throws IndexOutOfBoundsException if {@code idx} is less than 0 or greater than or equal to {@code size(key)}
     */
    default void removeRange(String key, int from, int to) {
        for (int i = to - 1; i >= from; i --) {
            remove(key, i);
        }
    }

    /**
     * Get the first value mapped to the given key.
     *
     * @param key the key
     * @return the value
     * @throws IndexOutOfBoundsException if there are no values for the given key
     */
    default String getFirst(String key) {
        return get(key, 0);
    }

    /**
     * Get the last value mapped to the given key.
     *
     * @param key the key
     * @return the value
     * @throws IndexOutOfBoundsException if there are no values for the given key
     */
    default String getLast(String key) {
        return get(key, size(key) - 1);
    }

    /**
     * Add a value before the first mapping for the given key.
     *
     * @param key the key
     * @param value the value
     */
    default void addFirst(String key, String value) {
        add(key, 0, value);
    }

    /**
     * Add a value after the last mapping for the given key.
     *
     * @param key the key
     * @param value the value
     */
    default void addLast(String key, String value) {
        add(key, size(key), value);
    }

    /**
     * Remove the first value mapped to the given key.
     *
     * @param key the key
     * @return the value
     * @throws IndexOutOfBoundsException if there are no values for the given key
     */
    default String removeFirst(String key) {
        return remove(key, 0);
    }

    /**
     * Remove the last value mapped to the given key.
     *
     * @param key the key
     * @return the value
     * @throws IndexOutOfBoundsException if there are no values for the given key
     */
    default String removeLast(String key) {
        return remove(key, size(key) - 1);
    }

    /**
     * Remove the mapping for the given key at the given position if it matches the given existing value.  All later
     * entries for that key are shifted up to fill in the gap left by the removed element.
     *
     * @param key the key
     * @param idx the index
     * @param value the expected previous mapping value
     * @return {@code true} if the value matched and was removed, {@code false} otherwise
     * @throws IndexOutOfBoundsException if {@code idx} is less than 0 or greater than or equal to {@code size(key)}
     */
    default boolean remove(String key, int idx, String value) {
        if (get(key, idx).equals(value)) {
            remove(key, idx);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Remove the first occurrence of the given value under the given key, if any.
     *
     * @param key the key
     * @param value the value to remove
     * @return {@code true} if the value was found and removed, {@code false} otherwise
     */
    default boolean removeFirst(String key, String value) {
        final int idx = indexOf(key, value);
        return idx >= 0 && remove(key, idx, value);
    }

    /**
     * Remove the last occurrence of the given value under the given key, if any.
     *
     * @param key the key
     * @param value the value to remove
     * @return {@code true} if the value was found and removed, {@code false} otherwise
     */
    default boolean removeLast(String key, String value) {
        final int idx = lastIndexOf(key, value);
        return idx >= 0 && remove(key, idx, value);
    }

    /**
     * Remove the all occurrences of the given value under the given key, if any.
     *
     * @param key the key
     * @param value the value to remove
     * @return {@code true} if the value was found and removed, {@code false} otherwise
     */
    default boolean removeAll(String key, String value) {
        int idx = lastIndexOf(key, value);
        if (idx == -1) return false;
        while (idx >= 0) {
            remove(key, idx, value);
            idx = lastIndexOf(key, value);
        }
        return true;
    }

    /**
     * Add all the values from the given map to this attributes collection.
     *
     * @param map the map to copy from
     * @return {@code true} if elements were added, {@code false} otherwise
     */
    default boolean addAll(Map<String, ? extends Collection<String>> map) {
        Assert.checkNotNullParam("map", map);
        boolean changed = false;
        for (Map.Entry<String, ? extends Collection<String>> entry : map.entrySet()) {
            final Collection<String> value = entry.getValue();
            if (value != null && ! value.isEmpty()) {
                final String key = entry.getKey();
                changed = addAll(key, value) || changed;
            }
        }
        return changed;
    }

    /**
     * Add all the values from the given collection to the value collection for the given key.
     *
     * @param key the key
     * @param values the values to add
     * @return {@code true} if elements were added, {@code false} otherwise
     */
    default boolean addAll(String key, Collection<String> values) {
        Assert.checkNotNullParam("key", key);
        Assert.checkNotNullParam("values", values);
        boolean changed = false;
        for (String s : values) {
            if (s != null) {
                addLast(key, s);
                changed = true;
            }
        }
        return changed;
    }

    /**
     * Determine if the given key has values in this collection.
     *
     * @param key the key
     * @return {@code true} if the key has values, {@code false} otherwise
     */
    default boolean containsKey(String key) {
        return key != null && size(key) > 0;
    }

    /**
     * Determine if the given key has a mapping for the given value in this collection.
     *
     * @param key the key
     * @param value the value
     * @return {@code true} if the key has a mapping to the given value, {@code false} otherwise
     */
    default boolean containsValue(String key, String value) {
        return key != null && value != null && indexOf(key, value) >= 0;
    }

    /**
     * Replace the mapping for the given key with the values copied from the given collection.
     *
     * @param key the key
     * @param values the new values
     * @return a list containing the previously mapped values
     */
    default List<String> copyAndReplace(String key, Collection<String> values) {
        final List<String> old = copyAndRemove(key);
        addAll(key, values);
        return old;
    }

    /**
     * Determine if this collection is empty.
     *
     * @return {@code true} if the collection is empty, {@code false} otherwise
     */
    default boolean isEmpty() {
        return size() == 0;
    }

    /**
     * Get the collection of values for the given key.  The result may implement {@link SetEntry} if the values
     * are distinct (for example, a role or group set).
     *
     * @param key the attribute name
     * @return the (possibly empty) attribute value collection
     */
    Entry get(String key);

    /**
     * The entry collection for a mapping.
     */
    interface Entry extends List<String> {

        /**
         * Get the mapping key.
         *
         * @return the mapping key
         */
        String getKey();

        /**
         * Remove all the values for the given key between the {@code from} index (inclusive) and the {@code to} index
         * (exclusive).
         *
         * @param from the start index (inclusive)
         * @param to the end index (exclusive)
         * @throws IndexOutOfBoundsException if {@code from} or {@code to} is outside of the allowed range
         */
        void removeRange(int from, int to);

        /**
         * Create a spliterator over the elements of this ordered and non-null collection.
         *
         * @return the spliterator
         */
        default Spliterator<String> spliterator() {
            return Spliterators.spliterator(this, Spliterator.ORDERED | Spliterator.NONNULL);
        }
    }

    /**
     * The entry collection for a mapping whose values are a distinct set.
     */
    interface SetEntry extends Entry, Set<String> {

        /**
         * Create a spliterator over the elements of this distinct, ordered, and non-null collection.
         *
         * @return the spliterator
         */
        default Spliterator<String> spliterator() {
            return Spliterators.spliterator(this, Spliterator.DISTINCT | Spliterator.ORDERED | Spliterator.NONNULL);
        }
    }
}
