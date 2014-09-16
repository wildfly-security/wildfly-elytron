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

import java.io.CharArrayReader;
import java.io.IOException;
import java.util.NoSuchElementException;

/**
 * This class can be used as a character-input stream.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class CharacterArrayReader extends CharArrayReader {

    public CharacterArrayReader(final char[] buf) {
        super(buf);
    }

    public CharacterArrayReader(final char[] buf, final int offset, final int length) {
        super(buf, offset, length);
    }

    public CharacterArrayReader(final char[] buf, final int offset) {
        super(buf, offset, buf.length - offset);
    }

    @Override
    public int read() throws IOException, NoSuchElementException {
        int ch = super.read();
        if (ch == -1) {
            throw new NoSuchElementException();
        }
        return ch;
    }

    @Override
    public int read(char b[], int off, int len) throws IOException, NoSuchElementException {
        int ch = super.read(b, off, len);
        if (ch == -1) {
            throw new NoSuchElementException();
        }
        return ch;
    }

    public int distanceTo(int ch) {
        for (int p = 0; pos + p < buf.length; p++) {
            if (buf[p + pos] == ch) {
                return p;
            }
        }
        return -1;
    }

    public boolean contentEquals(String other) {
        return Arrays2.equals(buf, pos, other);
    }
}
