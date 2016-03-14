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

import java.util.HashMap;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;

/**
 * An indexed enumeration of strings.  The enumeration can look up string indexes by number, numeric indexes by string,
 * or retrieve the interned string value by name.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class StringEnumeration {
    private final HashMap<String, Data> index;
    private final Data[] byId;

    private StringEnumeration(final HashMap<String, Data> index, final Data[] byId) {
        this.index = index;
        this.byId = byId;
    }

    /**
     * Construct a new instance.  The given values are used as the string members in the order they are given.
     *
     * @param values the values
     * @return the string enumeration
     */
    public static StringEnumeration of(String... values) {
        final int length = values.length;
        Data[] byId = new Data[length];
        HashMap<String, Data> index = new HashMap<>(length);
        String str;
        for (int i = 0; i < length; i ++) {
            str = Assert.checkNotNullArrayParam("values", i, values[i]);
            index.put(str, byId[i] = new Data(i, str));
        }
        return new StringEnumeration(index, byId);
    }

    /**
     * Get the canonical name for a string.  If the string is not found, an exception is thrown.
     *
     * @param str the string to look up (must not be {@code null})
     * @return the canonical name (not {@code null})
     */
    public String canonicalName(String str) {
        final Data data = index.get(str);
        if (data == null) {
            throw ElytronMessages.log.generalInvalidName(str);
        }
        return data.canonicalName;
    }

    /**
     * Get the numeric index for a string.  If the string is not found, an exception is thrown.
     *
     * @param str the string to look up (must not be {@code null})
     * @return the numeric index
     */
    public int indexOf(String str) {
        final Data data = index.get(str);
        if (data == null) {
            throw ElytronMessages.log.generalInvalidName(str);
        }
        return data.index;
    }

    /**
     * Get the canonical name for an index.  If the index is out of range, an exception is thrown.
     *
     * @param index the index to seek
     * @return the canonical name (not {@code null})
     */
    public String nameOf(int index) {
        final Data[] byId = this.byId;
        Assert.checkMinimumParameter("index", 0, index);
        Assert.checkMaximumParameter("index", size() - 1, index);
        return byId[index].canonicalName;
    }

    /**
     * Get the size of this enumeration.
     *
     * @return the size of this enumeration
     */
    public int size() {
        return byId.length;
    }

    static class Data {
        final int index;
        final String canonicalName;

        Data(final int index, final String canonicalName) {
            this.index = index;
            this.canonicalName = canonicalName;
        }
    }
}
