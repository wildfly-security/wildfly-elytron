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

package org.wildfly.security.auth.server;

import java.io.Closeable;
import java.io.IOException;
import java.util.Iterator;

/**
 * Iterator providing close() method to free resources before end of iterating.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public interface CloseableIterator<E> extends Iterator<E>, Closeable {

    /**
     * Close any underlying resources. No need to call if end of sequence already occurred.
     */
    default void close() throws IOException {}

    /**
     * Returns an iterator that has no elements and is closeable.
     * @param <T> the type of elements of this iterator
     * @return empty closeable iterator
     */
    static <T> CloseableIterator<T> emptyIterator() {
        return new CloseableIterator<T>() {
            @Override
            public boolean hasNext() {
                return false;
            }
            @Override
            public T next() {
                return null;
            }
        };
    }

}
