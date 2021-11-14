/*
 * Copyright 2021 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.http.sfbasic;

import static org.wildfly.security.mechanism._private.ElytronMessages.httpBasic;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.cache.CachedIdentity;

/**
 * Manager class responsible for handling the cached identities.
 *
 * This implementation uses a coarse synchronization lock on the whole identity
 * manager as the operations are largely direct maniuplation of the underlying
 * collection.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class IdentityManager {

    /**
     * Fifteen minutes.
     */
    private static final long MAX_VALIDITY = 15 * 60 * 1000;

    /**
     * This class is generating session IDs so these must be secure.
     */
    private final Random random = new SecureRandom();

    /**
     * Executor to handle session eviction.
     */
    private final ScheduledExecutorService executor;

    /**
     * Map of the presently cached identities.
     */
    private final Map<String, StoredIdentity> storedIdentities = new HashMap<>();

    IdentityManager() {
        ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1);
        executor.setRemoveOnCancelPolicy(true);
        executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);

        this.executor = executor;
    }

    synchronized String storeIdentity(final String existingSessionID, final CachedIdentity cachedIdentity) {
        if (existingSessionID != null) {
            StoredIdentity storedIdentity = storedIdentities.get(existingSessionID);
            if (storedIdentity != null) {
                storedIdentity.setCachedIdentity(cachedIdentity);
                storedIdentity.used(existingSessionID);

                httpBasic.tracef("Updating cached identity for session '%s'", existingSessionID);
                return existingSessionID;
            }
        }

        String sessionID =  null;
        while (sessionID == null || storedIdentities.containsKey(sessionID)) {
            sessionID = generateSessionID();
        }

        if (httpBasic.isTraceEnabled()) {
            httpBasic.tracef("Creating new session '%s' for identity '%s'.", sessionID, cachedIdentity.getName());
        }

        StoredIdentity toStore = new StoredIdentity(cachedIdentity);
        toStore.used(sessionID);
        storedIdentities.put(sessionID, toStore);

        return sessionID;
    }

    synchronized CachedIdentity retrieveIdentity(final String sessionID) {
        StoredIdentity stored = storedIdentities.get(sessionID);
        if (stored != null) {
            if (System.currentTimeMillis() - stored.getLastAccessed() > MAX_VALIDITY) {
                httpBasic.tracef("Removing session '%s' due to request to use beyond validity period.", sessionID);
                stored.cancelCleanup();
                storedIdentities.remove(sessionID);
            } else {
                stored.used(sessionID);

                return stored.getCachedIdentity();
            }
        }

        return null;
    }

    synchronized CachedIdentity removeIdentity(final String sessionID) {
        StoredIdentity stored = storedIdentities.remove(sessionID);
        if (stored != null) {
            stored.cancelCleanup();
            httpBasic.tracef("Removing session '%s' due to request to remove.", sessionID);
        }

        return stored != null ? stored.getCachedIdentity() : null;
    }

    private synchronized void evict(final String sessionID, final long forLastAccessed) {
        StoredIdentity stored = storedIdentities.get(sessionID);
        if (stored != null) {
            if (stored.getLastAccessed() == forLastAccessed) {
                storedIdentities.remove(sessionID);
                httpBasic.tracef("Removing session '%s' due to timeout.", sessionID);
            } else {
                // To hit this maybe the eviction task could not be successfully cancelled but the session
                // was subsequently used.
                httpBasic.tracef("Not evicting session '%s' due to different lastAccessed.", sessionID);
            }
        } else {
            httpBasic.tracef("Session '%s' due for eviction but not in the stored identities.", sessionID);
        }
    }

    private String generateSessionID() {
        // OWASP recommendation of 128 bits minimum.
        byte[] rawId = new byte[16];
        random.nextBytes(rawId);
        // TODO - We could use a counter in addition to the 128 bits to guarantee a unique session ID.

        return ByteIterator.ofBytes(rawId).base64Encode().drainToString();
    }

    void shutdown() {
        this.executor.shutdown();
    }

    private class StoredIdentity {

        // This class is only accessed in synchronised methods so we
        // do not need the member variables to be volatile.

        private CachedIdentity cachedIdentity;
        private long lastAccessed;
        private ScheduledFuture<?> futureCleanup;

        StoredIdentity(final CachedIdentity cachedIdentity) {
            this.cachedIdentity = cachedIdentity;
            this.lastAccessed = System.currentTimeMillis();
        }

        protected CachedIdentity getCachedIdentity() {
            return cachedIdentity;
        }

        void setCachedIdentity(CachedIdentity cachedIdentity) {
            this.cachedIdentity = cachedIdentity;
        }

        protected long getLastAccessed() {
            return lastAccessed;
        }

        void used(final String sessionID) {
            cancelCleanup();
            final long ourLastAccessed = lastAccessed = System.currentTimeMillis();

            futureCleanup = executor.schedule(() -> evict(sessionID, ourLastAccessed), 15, TimeUnit.MINUTES);
        }

        void cancelCleanup() {
            if (futureCleanup != null) {
                futureCleanup.cancel(true);
                futureCleanup = null;
            }
        }

    }
}
