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

package org.wildfly.security.manager;

import java.lang.reflect.Field;
import java.security.PrivilegedAction;

/**
 * A privileged action which gets and returns a non-public field from a class.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
// note: don't make this public.  people should generally use the reflection index for this kind of thing.
final class GetAccessibleDeclaredFieldAction implements PrivilegedAction<Field> {
    private final Class<?> clazz;
    private final String fieldName;

    /**
     * Construct a new instance.
     *
     * @param clazz the class to search
     * @param fieldName the field name to search for
     */
    public GetAccessibleDeclaredFieldAction(final Class<?> clazz, final String fieldName) {
        this.clazz = clazz;
        this.fieldName = fieldName;
    }

    public Field run() {
        final Field field;
        try {
            field = clazz.getDeclaredField(fieldName);
        } catch (NoSuchFieldException e) {
            throw new NoSuchFieldError(e.getMessage());
        }
        field.setAccessible(true);
        return field;
    }
}
