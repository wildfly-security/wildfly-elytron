/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import java.util.function.Function;

import org.wildfly.common.Assert;

/**
 * An efficient mapping of enumerated strings to some other object.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class StringMapping<T> {
    private final StringEnumeration stringEnumeration;
    private final T[] items;

    /**
     * Construct a new instance.
     *
     * @param stringEnumeration the string enumeration (must not be {@code null})
     * @param mapping the mapping function (must not be {@code null})
     */
    public StringMapping(final StringEnumeration stringEnumeration, final Function<String, T> mapping) {
        Assert.checkNotNullParam("stringEnumeration", stringEnumeration);
        Assert.checkNotNullParam("mapping", mapping);
        this.stringEnumeration = stringEnumeration;
        @SuppressWarnings("unchecked")
        final T[] items = (T[]) new Object[stringEnumeration.size()];
        for (int i = 0; i < stringEnumeration.size(); i ++) {
            items[i] = mapping.apply(stringEnumeration.nameOf(i));
        }
        this.items = items;
    }

    /**
     * Get an item from this mapping by ID.
     *
     * @param index the index to look up
     * @return the mapped item for the given ID
     * @throws IllegalArgumentException if the given index is out of range
     */
    public T getItemById(int index) throws IllegalArgumentException {
        Assert.checkMinimumParameter("index", 0, index);
        Assert.checkMaximumParameter("index", stringEnumeration.size() - 1, index);
        return items[index];
    }

    /**
     * Get an item from this mapping by the corresponding string name.
     *
     * @param str the string name
     * @return the item
     * @throws IllegalArgumentException if the string name is unknown
     */
    public T getItemByString(String str) throws IllegalArgumentException {
        Assert.checkNotNullParam("str", str);
        return items[stringEnumeration.indexOf(str)];
    }

    /**
     * Get the string enumeration for this mapping.
     *
     * @return the string enumeration for this mapping (not {@code null})
     */
    public StringEnumeration getStringEnumeration() {
        return stringEnumeration;
    }
}
