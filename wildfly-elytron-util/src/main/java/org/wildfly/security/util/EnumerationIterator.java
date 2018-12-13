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

import java.util.Enumeration;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * An enumeration which is also an iterator.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface EnumerationIterator<E> extends Enumeration<E>, Iterator<E> {
    /**
     * Determine if there are more elements to iterate over in the direction of this iterator.
     *
     * @return {@code true} if there are more elements, {@code false} otherwise
     */
    default boolean hasMoreElements() {
        return hasNext();
    }

    /**
     * Get the next element in the direction of this iterator.
     *
     * @return the next element
     */
    default E nextElement() {
        return next();
    }

    /**
     * Get an enumeration iterator over one element.
     *
     * @param item the element
     * @param <E> the element type
     * @return the enumeration iterator
     */
    static <E> EnumerationIterator<E> over(E item) {
        return new EnumerationIterator<E>() {
            boolean done;
            public boolean hasNext() {
                return ! done;
            }

            public E next() {
                if (! hasNext()) throw new NoSuchElementException();
                done = true;
                return item;
            }
        };
    }
}
