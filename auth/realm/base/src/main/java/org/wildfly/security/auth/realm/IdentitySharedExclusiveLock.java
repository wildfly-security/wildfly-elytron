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

/**
 * A simple shared/exclusive lock for a realm identity.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class IdentitySharedExclusiveLock {

    private int sharedHoldCount;
    private boolean isExclusiveLocked;
    private int exclusiveRequests;

    /**
     * Acquire the exclusive lock. An invocation of this method will block until the lock can be acquired.
     *
     * @return a lock object representing the newly acquired lock
     */
    public synchronized IdentityLock lockExclusive() {
        boolean interrupted = false;
        try {
            exclusiveRequests++;
            while ((sharedHoldCount > 0) || isExclusiveLocked) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
            isExclusiveLocked = true;
            exclusiveRequests--;
            return new IdentityLock(true);
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }

    }

    /**
     * Acquire a shared lock. An invocation of this method will block until the lock can be acquired.
     *
     * @return a lock object representing the newly acquired lock
     */
    public synchronized IdentityLock lockShared() {
        boolean interrupted = false;
        try {
            while (isExclusiveLocked || (exclusiveRequests > 0)) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
            sharedHoldCount++;
            return new IdentityLock(false);
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private synchronized void release(IdentityLock identityLock) {
        if (identityLock.isExclusive()) {
            isExclusiveLocked = false;
            notifyAll();
        } else {
            if (--sharedHoldCount == 0) {
                notifyAll();
            }
        }

    }

    /**
     * Class that represents a lock on a realm identity. A lock object is created each time a lock is
     * acquired on a realm identity via {@link IdentitySharedExclusiveLock#lockExclusive()} or
     * {@link IdentitySharedExclusiveLock#lockShared()}.
     */
    public class IdentityLock implements AutoCloseable {

        private final boolean exclusive;
        private volatile boolean valid = true;

        /**
         * Construct a new instance.
         *
         * @param exclusive {@code true} if this lock is exclusive, {@code false} if this lock is shared
         */
        public IdentityLock(final boolean exclusive) {
            this.exclusive = exclusive;
        }

        /**
         * Release this lock. Invoking this method has no effect if this lock is invalid.
         */
        public synchronized void release() {
            if (valid) {
                IdentitySharedExclusiveLock.this.release(this);
                valid = false;
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
