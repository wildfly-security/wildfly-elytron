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
package org.wildfly.security.auth.realm.token.validator;

import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.pem.PemEntry;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.PublicKey;
import java.util.Iterator;

import static org.wildfly.security.auth.realm.token._private.ElytronMessages.log;

/**
 * Transitional holder for the {@code publicKeyUrl} (non-JKU, single-PEM-key) remote key resolution
 * introduced by ELY-3066. The JWKS-based ({@code jku}/{@code jkuFallbackUrl}) fetching this class used
 * to also own has already been migrated to {@code JwksCache} as part of the JWKS unification (ELY-2924);
 * this remainder will itself be folded into the consolidated key manager in a follow-up commit.
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
class JwkManager {

    private final SSLContext sslContext;
    private final HostnameVerifier hostnameVerifier;

    private final long updateTimeout;
    private final int minTimeBetweenRequests;

    private final int connectionTimeout;
    private final int readTimeout;

    // State for the configured remote public key URL (non-JKU path)
    private final URL publicKeyUrl;
    private volatile PublicKey cachedPublicKey;
    private volatile long cachedPublicKeyTimestamp = 0;

    JwkManager(SSLContext sslContext, HostnameVerifier hostnameVerifier, long updateTimeout, int connectionTimeout, int readTimeout, int minTimeBetweenRequests, URL publicKeyUrl) {
        this.sslContext = sslContext;
        this.hostnameVerifier = hostnameVerifier;
        this.updateTimeout = updateTimeout;
        this.connectionTimeout = connectionTimeout;
        this.readTimeout = readTimeout;
        this.minTimeBetweenRequests = minTimeBetweenRequests;
        this.publicKeyUrl = publicKeyUrl;
    }

    boolean hasPublicKeyUrl() {
        return publicKeyUrl != null;
    }

    /**
     * Returns the public key from the configured remote URL, fetching it if the cache has expired.
     * If {@code forceRefresh} is true, bypasses the TTL check and re-fetches — but the
     * min-time-between-requests guard still applies to prevent DoS of the key server.
     */
    synchronized PublicKey getRemotePublicKey(boolean forceRefresh) {
        long currentTime = System.currentTimeMillis();
        boolean cacheValid = cachedPublicKey != null && (cachedPublicKeyTimestamp + updateTimeout > currentTime);

        if (!forceRefresh && cacheValid) {
            return cachedPublicKey;
        }

        // Respect the minimum time between requests even on a forced refresh
        if (cachedPublicKeyTimestamp + minTimeBetweenRequests > currentTime) {
            log.avoidingFetchRemotePublicKey(publicKeyUrl, cachedPublicKeyTimestamp);
            return cachedPublicKey;
        }

        PublicKey fetched = fetchPublicKeyFromUrl(publicKeyUrl, sslContext, hostnameVerifier, connectionTimeout, readTimeout);
        if (fetched != null) {
            cachedPublicKey = fetched;
            cachedPublicKeyTimestamp = currentTime;
        } else {
            log.unableToFetchRemotePublicKey(publicKeyUrl.toString());
        }
        return cachedPublicKey;
    }

    private static PublicKey fetchPublicKeyFromUrl(URL url, SSLContext sslContext, HostnameVerifier hostnameVerifier, int connectionTimeout, int readTimeout) {
        InputStream inputStream = null;
        try {
            URLConnection connection = url.openConnection();
            connection.setConnectTimeout(connectionTimeout);
            connection.setReadTimeout(readTimeout);
            if (connection instanceof HttpsURLConnection && sslContext != null) {
                HttpsURLConnection httpsConn = (HttpsURLConnection) connection;
                httpsConn.setSSLSocketFactory(sslContext.getSocketFactory());
                if (hostnameVerifier != null) {
                    httpsConn.setHostnameVerifier(hostnameVerifier);
                }
            }
            connection.connect();
            inputStream = connection.getInputStream();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(chunk)) != -1) {
                buffer.write(chunk, 0, bytesRead);
            }
            Iterator<PemEntry<?>> pemEntries = Pem.parsePemContent(CodePointIterator.ofUtf8Bytes(buffer.toByteArray()));
            if (!pemEntries.hasNext()) {
                log.warn("Remote public key URL returned no PEM content: " + url);
                return null;
            }
            PublicKey publicKey = pemEntries.next().tryCast(PublicKey.class);
            if (publicKey == null) {
                log.warn("Remote public key URL did not return a valid public key: " + url);
            }
            return publicKey;
        } catch (IOException e) {
            log.warn("Unable to connect to remote public key URL: " + url);
            return null;
        } finally {
            if (inputStream != null) {
                try { inputStream.close(); } catch (IOException ignored) {}
            }
        }
    }
}
