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

package org.wildfly.security.pem;

import org.wildfly.common.Assert;

/**
 * An entry in a PEM file or stream.
 *
 * @param <T> the entry type
 */
public final class PemEntry<T> {
    private final T entry;

    /**
     * Construct a new instance.
     *
     * @param entry the entry value (not {@code null})
     */
    public PemEntry(final T entry) {
        Assert.checkNotNullParam("entry", entry);
        this.entry = entry;
    }

    /**
     * Get the entry value.
     *
     * @return the entry value (not {@code null})
     */
    public T getEntry() {
        return entry;
    }

    /**
     * Try to cast this entry's value to the given type.
     *
     * @param clazz the type class to attempt to cast to (not {@code null})
     * @param <U> the type to attempt to cast to
     * @return the cast value, or {@code null} if the type does not match
     */
    public <U> U tryCast(Class<U> clazz) {
        final T entry = this.entry;
        return clazz.isInstance(entry) ? clazz.cast(entry) : null;
    }
}
