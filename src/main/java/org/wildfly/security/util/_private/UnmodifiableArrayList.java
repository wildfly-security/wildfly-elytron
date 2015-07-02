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

package org.wildfly.security.util._private;

import static org.wildfly.security._private.ElytronMessages.log;

import java.util.AbstractList;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class UnmodifiableArrayList<T> extends AbstractList<T> {
    private final T[] items;

    @SafeVarargs
    public UnmodifiableArrayList(final T... items) {
        this.items = items;
    }

    public T get(final int index) {
        try {
            return items[index];
        } catch (ArrayIndexOutOfBoundsException e) {
            throw log.invalidIndex(index);
        }
    }

    public int size() {
        return items.length;
    }
}
