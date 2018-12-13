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

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

import org.wildfly.security.util.ElytronMessages;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AtomicFileOutputStream extends OutputStream {
    private volatile State current;

    private static final AtomicReferenceFieldUpdater<AtomicFileOutputStream, State> currentUpdater = AtomicReferenceFieldUpdater.newUpdater(AtomicFileOutputStream.class, State.class, "current");

    public AtomicFileOutputStream(final String name) throws IOException {
        this(Paths.get(name));
    }

    public AtomicFileOutputStream(final File file) throws IOException {
        this(file.toPath());
    }

    public AtomicFileOutputStream(final Path path) throws IOException {
        final Path parent = path.getParent();
        if (parent != null && parent.getNameCount() != 0 && ! Files.exists(parent)) {
            Files.createDirectories(parent);
        }
        current = new OpenState(Files.newOutputStream(path.resolveSibling(path.getFileName() + ".new"), CREATE, TRUNCATE_EXISTING), path);
    }

    public void flush() throws IOException {
        current.flush();
    }

    public void close() throws IOException {
        current.close();
    }

    public void write(final int b) throws IOException {
        current.write(b);
    }

    public void write(final byte[] bytes, final int off, final int len) throws IOException {
        current.write(bytes, off, len);
    }

    boolean casCurrent(State expect, State update) {
        return currentUpdater.compareAndSet(this, expect, update);
    }

    public void cancel() throws IOException {
        current.cancel();
    }

    abstract static class State {
        abstract void write(int b) throws IOException;

        abstract void write(byte[] b, int off, int len) throws IOException;

        abstract void flush() throws IOException;

        abstract void close() throws IOException;

        abstract void cancel() throws IOException;
    }

    final class OpenState extends State {
        private final OutputStream delegate;
        private final Path path;

        OpenState(final OutputStream delegate, final Path path) {
            this.delegate = delegate;
            this.path = path;
        }

        void write(final int b) throws IOException {
            delegate.write(b);
        }

        void write(final byte[] b, final int off, final int len) throws IOException {
            delegate.write(b, off, len);
        }

        void flush() throws IOException {
            delegate.flush();
        }

        void close() throws IOException {
            if (casCurrent(this, CLOSED)) {
                // atomic cleanup operation: close out our stream
                delegate.close();
                final Path path = this.path;
                final Path newPath = path.resolveSibling(path.getFileName() + ".new");
                try {
                    // move new file in
                    Files.move(newPath, path, REPLACE_EXISTING, ATOMIC_MOVE);
                } catch (Throwable t) {
                    try {
                        // didn't work, gotta delete our temp copy
                        Files.deleteIfExists(newPath);
                    } catch (Throwable problem) {
                        problem.addSuppressed(t);
                        throw problem;
                    }
                    throw t;
                }
            }
        }

        void cancel() throws IOException {
            if (casCurrent(this, CLOSED)) {
                delegate.close();
                final Path newPath = path.resolveSibling(path.getFileName() + ".new");
                Files.deleteIfExists(newPath);
            }
        }
    }

    private static final State CLOSED = new State() {
        void write(final int b) throws IOException {
            throw ElytronMessages.log.closed();
        }

        void write(final byte[] b, final int off, final int len) throws IOException {
            throw ElytronMessages.log.closed();
        }

        void flush() throws IOException {
            throw ElytronMessages.log.closed();
        }

        void close() throws IOException {
            // no op
        }

        void cancel() throws IOException {
            // no op
        }
    };
}
