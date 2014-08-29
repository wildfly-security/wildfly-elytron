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

import java.util.NoSuchElementException;

/**
 * An iterator for byte arrays.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class ByteArrayIterator {

    private final byte[] b;
    private int i;

    public ByteArrayIterator(final byte[] b) {
        this.b = b;
    }

    public ByteArrayIterator(final byte[] b, final int i) {
        if (i < 0 || i >= b.length) {
            throw new NoSuchElementException();
        }
        this.b = b;
        this.i = i;
    }

    public boolean hasNext() {
        return i < b.length;
    }

    public int next() throws NoSuchElementException {
        if (! hasNext()) {
            throw new NoSuchElementException();
        }
        return lookup(i++);
    }

    protected int lookup(int idx) {
        return b[idx] & 0xff;
    }
}
