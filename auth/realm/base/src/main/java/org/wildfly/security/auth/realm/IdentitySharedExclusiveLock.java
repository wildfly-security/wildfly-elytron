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

package org.wildfly.security.auth.realm;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * A simple shared/exclusive lock for a realm identity.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class IdentitySharedExclusiveLock {

    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock(true);

    /**
     * Acquire the exclusive lock. An invocation of this method will block until the lock can be acquired,
     * or the thread is interrupted.
     *
     * @return a lock object representing the newly acquired lock
     * @throws InterruptedException if the current thread is interrupted while waiting for the lock
     */
    public IdentityLock lockExclusive() throws InterruptedException {
        readWriteLock.writeLock().lockInterruptibly();
        return new IdentityLock(true, readWriteLock.writeLock());
    }

    /**
     * Acquire a shared lock. An invocation of this method will block until the lock can be acquired,
     * or the thread is interrupted.
     *
     * @return a lock object representing the newly acquired lock
     * @throws InterruptedException if the current thread is interrupted while waiting for the lock
     */
    public IdentityLock lockShared() throws InterruptedException {
        readWriteLock.readLock().lockInterruptibly();
        return new IdentityLock(false, readWriteLock.readLock());
    }

    /**
     * Class that represents a lock on a realm identity. A lock object is created each time a lock is
     * acquired on a realm identity via {@link IdentitySharedExclusiveLock#lockExclusive()} or
     * {@link IdentitySharedExclusiveLock#lockShared()}.
     */
    public class IdentityLock implements AutoCloseable {

        private final boolean exclusive;
        private final Lock internalLock;
        private volatile boolean valid = true;

        /**
         * Construct a new instance.
         *
         * @param exclusive {@code true} if this lock is exclusive, {@code false} if this lock is shared
         * @param internalLock the underlying lock instance
         */
        public IdentityLock(final boolean exclusive, final Lock internalLock) {
            this.exclusive = exclusive;
            this.internalLock = internalLock;
        }

        /**
         * Release this lock. Invoking this method has no effect if this lock is invalid.
         */
        public void release() {
            synchronized (this) {
                if (valid) {
                    internalLock.unlock();
                    valid = false;
                }
            }
        }

        @Override
        public void close() {
            release();
        }

        /**
         * Determine whether this lock is exclusive or shared.
         *
         * @return {@code true} if this lock is exclusive, {@code false} if this lock is shared
         */
        public boolean isExclusive() {
            return exclusive;
        }

        /**
         * Determine whether this lock is valid. A lock starts out valid and becomes invalid when it
         * is released via {@link #release()} or {@link #close()}.
         *
         * @return {@code true} if this lock is valid, {@code false} otherwise
         */
        public boolean isValid() {
            return valid;
        }
    }
}
