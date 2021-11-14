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
import java.util.concurrent.ScheduledThreadPoolExecutor;

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.cache.CachedIdentity;

/**
 * Manager class responsible for handling the cached identities.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class IdentityManager {

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
    private final Map<String, StoredIdentity> cachedIdentities = new HashMap<>();

    IdentityManager() {
        ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1);
        executor.setRemoveOnCancelPolicy(true);
        executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);

        this.executor = executor;
    }

    String storeIdentity(final String existingSessionID, final CachedIdentity cachedIdentity) {
        if (existingSessionID != null) {
            StoredIdentity storedIdentity = cachedIdentities.get(existingSessionID);
            if (storedIdentity != null) {
                storedIdentity.setCachedIdentity(cachedIdentity);
                storedIdentity.setLastAccessed(System.currentTimeMillis());

                httpBasic.tracef("Updating cached identity for session '%s'", existingSessionID);
                return existingSessionID;
            }
        }



        String sessionID =  null;
        while (sessionID == null || cachedIdentities.containsKey(sessionID)) {
            sessionID = generateSessionID();
        }

        if (httpBasic.isTraceEnabled()) {
            httpBasic.tracef("Creating new session '%s' for identity '%s'.", sessionID, cachedIdentity.getName());
        }

        // TODO Use a synchronized store method, this will also allow us to set a time to
        // invalidate the session.
        cachedIdentities.put(sessionID, new StoredIdentity(sessionID, cachedIdentity));

        return sessionID;
    }

    CachedIdentity retrieveIdentity(final String sessionID) {
        // TODO Retrieval will need to rest the last used time and update the eviction task.

        // TODO We should still check the last accessed time as it is not guaranteed the eviction task
        // will have executed on time.

        StoredIdentity stored = cachedIdentities.get(sessionID);
        return stored != null ? stored.getCachedIdentity() : null;
    }

    CachedIdentity removeIdentity(final String sessionID) {
        // TODO Any related eviction task will need cancelling.

        StoredIdentity stored = cachedIdentities.remove(sessionID);
        if (stored != null) {
            httpBasic.tracef("Removing session '%s' due to request to remove.", sessionID);
        }

        return stored != null ? stored.getCachedIdentity() : null;
    }

    private String generateSessionID() {
        // OWASP recommendation of 128 bits minimum.
        byte[] rawId = new byte[16];
        random.nextBytes(rawId);
        // TODO - We could use a counter in addition to the 128 bits to guarantee a unique session ID.

        return ByteIterator.ofBytes(rawId).base64Encode().drainToString();
    }

    private static class StoredIdentity {

        private final String sessionID;
        private volatile CachedIdentity cachedIdentity;
        private volatile long lastAccessed;

        StoredIdentity(final String sessionID, final CachedIdentity cachedIdentity) {
            this.sessionID = sessionID;
            this.cachedIdentity = cachedIdentity;
            this.lastAccessed = System.currentTimeMillis();
        }

        protected String getSessionID() {
            return sessionID;
        }

        protected CachedIdentity getCachedIdentity() {
            return cachedIdentity;
        }

        void setCachedIdentity(CachedIdentity cachedIdentity) {
            this.cachedIdentity = cachedIdentity;
        }

        void setLastAccessed(long lastAccessed) {
            this.lastAccessed = lastAccessed;
        }

        protected long getLastAccessed() {
            return lastAccessed;
        }
    }
}
