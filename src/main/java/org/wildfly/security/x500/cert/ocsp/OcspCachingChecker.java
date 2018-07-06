/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert.ocsp;

import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An OCSP checker which cache responses of an other OCSP checker in LRU in-memory cache.
 */
public class OcspCachingChecker implements OcspChecker {

    private final OcspChecker source;
    private final long maxAge;
    private final int maxEntries;

    private final Map<CertId, CacheEntry> cache = new LinkedHashMap<CertId, CacheEntry>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry eldest) {
            return cache.size() > maxEntries;
        }
    };

    /**
     * Construct an caching checker.
     * @param source the source OCSP checker
     * @param maxAge the maximum age of record in the cache in miliseconds
     * @param maxEntries the maximum amount of records in the cache
     */
    public OcspCachingChecker(OcspChecker source, long maxAge, int maxEntries) {
        this.source = source;
        this.maxAge = maxAge;
        this.maxEntries = maxEntries;
    }

    @Override
    public OcspStatus obtainStatus(CertId certId, X509Certificate issuer, URL responder, OcspSignatureVerifier signatureVerifier)
            throws CertificateException, IOException {
        CacheEntry entry = cache.get(certId);
        if (entry != null && ! entry.isExpired()) {
            return entry.getStatus();
        }
        OcspStatus status = source.obtainStatus(certId, issuer, responder, signatureVerifier);
        cache.put(certId, new CacheEntry(status, maxAge));
        return status;
    }

    private static final class CacheEntry {
        final OcspStatus status;
        final long expiration;

        CacheEntry(OcspStatus status, long maxAge) {
            this.status = status;
            if(maxAge == -1) {
                expiration = -1;
            } else {
                expiration = System.currentTimeMillis() + maxAge;
            }
        }

        OcspStatus getStatus() {
            return status;
        }

        boolean isExpired() {
            return expiration != -1 && System.currentTimeMillis() > expiration;
        }
    }

}
