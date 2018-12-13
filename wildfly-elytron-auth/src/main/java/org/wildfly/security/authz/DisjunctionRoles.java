/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.authz;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Spliterator;
import java.util.Spliterators;

class DisjunctionRoles implements Roles {

    private final Roles left;
    private final Roles right;

    DisjunctionRoles(final Roles left, final Roles right) {
        this.left = left;
        this.right = right;
    }

    public boolean contains(final String roleName) {
        return left.contains(roleName) != right.contains(roleName);
    }

    public boolean isEmpty() {
        return ! iterator().hasNext();
    }

    public Iterator<String> iterator() {
        final Iterator<String> leftIterator = left.iterator();
        final Iterator<String> rightIterator = right.iterator();
        return new Iterator<String>() {
            String next;

            public boolean hasNext() {
                if (next != null) {
                    return true;
                }
                for (;;) {
                    if (leftIterator.hasNext()) {
                        next = leftIterator.next();
                        if (! right.contains(next)) {
                            return true;
                        }
                        next = null;
                        // fall out and re-loop
                    } else if (rightIterator.hasNext()) {
                        next = rightIterator.next();
                        if (! left.contains(next)) {
                            return true;
                        }
                        next = null;
                        // fall out and re-loop
                    } else {
                        return false;
                    }
                }
            }

            public String next() {
                if (! hasNext()) {
                    throw new NoSuchElementException();
                }
                final String next = this.next;
                this.next = null;
                return next;
            }
        };
    }

    public Spliterator<String> spliterator() {
        return Spliterators.spliteratorUnknownSize(iterator(), Spliterator.NONNULL | Spliterator.DISTINCT);
    }
}
