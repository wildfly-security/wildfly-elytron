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

package org.wildfly.security.password.impl;

import static java.lang.Math.min;

/**
 * A simple array-backed character sequence with minimal overhead or error checking.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class CharArraySequence implements CharSequence {

    private final char[] array;
    private final int offs;
    private final int len;

    CharArraySequence(final char[] array) {
        this(array, 0, array.length);
    }

    CharArraySequence(final char[] array, final int offs, final int len) {
        this.array = array;
        this.offs = offs;
        this.len = len;
    }

    public int length() {
        return len;
    }

    public char charAt(final int index) {
        return array[index + offs];
    }

    public CharSequence subSequence(final int start, final int end) {
        return new CharArraySequence(array, start + offs, min(len, end - start));
    }
}
