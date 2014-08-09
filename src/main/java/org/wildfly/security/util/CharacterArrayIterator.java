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

package org.wildfly.security.util;

import java.security.spec.InvalidKeySpecException;
import java.util.NoSuchElementException;

/**
 * An iterator for character arrays.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class CharacterArrayIterator {

    private final char[] c;
    private int i;

    public CharacterArrayIterator(final char[] c) {
        this.c = c;
    }

    public CharacterArrayIterator(final char[] c, final int i) {
        this.c = c;
        this.i = i;
    }

    public boolean hasNext() {
        return i < c.length;
    }

    public int next() throws InvalidKeySpecException {
        if (! hasNext()) {
            throw new InvalidKeySpecException("Unexpected end of input string");
        }
        return c[i++];
    }

    public int current() {
        if (i == 0) throw new NoSuchElementException();
        return c[i - 1];
    }

    public int distanceTo(int ch) {
        for (int p = 0; i + p < c.length; p ++) {
            if (c[p + i] == ch) {
                return p;
            }
        }
        return -1;
    }

    public boolean contentEquals(String other) {
        return Arrays2.equals(c, i, other);
    }

    public void skip(final int cnt) {
        i += cnt;
    }

}
