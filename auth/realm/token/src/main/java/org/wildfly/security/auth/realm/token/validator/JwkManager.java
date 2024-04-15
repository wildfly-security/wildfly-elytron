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

import org.wildfly.common.Assert;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.wildfly.security.auth.realm.token._private.ElytronMessages.log;

/**
 * Object for caching RSA JSON Web Keys for signature validation
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
class JwkManager {

    private final Map<URL, CacheEntry> keys = new LinkedHashMap<>();
    private final SSLContext sslContext;
    private final HostnameVerifier hostnameVerifier;
    private final Set<String> allowedJkuValues;

    private final long updateTimeout;
    private final int minTimeBetweenRequests;

    private final int connectionTimeout;
    private final int readTimeout;

    JwkManager(SSLContext sslContext, HostnameVerifier hostnameVerifier, long updateTimeout, int connectionTimeout, int readTimeout, int minTimeBetweenRequests, Set<String> allowedJkuValues) {
        this.sslContext = sslContext;
        this.hostnameVerifier = hostnameVerifier;
        this.updateTimeout = updateTimeout;
        this.connectionTimeout = connectionTimeout;
        this.readTimeout = readTimeout;
        this.minTimeBetweenRequests = minTimeBetweenRequests;
        this.allowedJkuValues = allowedJkuValues;
    }

    /**
     * Thread-safe method for receiving remote public key
     * @param kid key id
     * @param url remote jkws url
     * @return signature verification public key if found, null otherwise
     */
    public PublicKey getPublicKey(String kid, URL url) {
        Map<String, RSAPublicKey> urlKeys = checkRemote(kid, url);

        if (urlKeys == null) {
            return null;
        }

        PublicKey pk = urlKeys.get(kid);
        if (pk == null) {
            log.warn("Unknown kid: " + kid);
            return null;
        }
        return pk;
    }

    private Map<String, RSAPublicKey> checkRemote(String kid, URL url) {
        Assert.checkNotNullParam("kid", kid);
        Assert.checkNotNullParam("url", url);

        CacheEntry cacheEntry;
        long lastUpdate;
        Map<String, RSAPublicKey> urlKeys;

        synchronized (keys) {
            cacheEntry = keys.get(url);
            if (cacheEntry == null) {
                cacheEntry = new CacheEntry();
                keys.put(url, cacheEntry);
            }
            lastUpdate = cacheEntry.getTimestamp();
            urlKeys = cacheEntry.getKeys();
        }

        long currentTime = System.currentTimeMillis();

        // check kid is in the entry and lastUpdate is inside the TTL
        if (urlKeys.containsKey(kid) && lastUpdate + updateTimeout > currentTime) {
            return urlKeys;
        }

        // check the minimum timeout to avoid flooding
        if (lastUpdate + minTimeBetweenRequests > currentTime) {
            log.avoidingFetchJwks(url, currentTime);
            return urlKeys;
        }

        // update the cached entry because cache is not valid
        synchronized (cacheEntry) {
            // re-check just in case another thread updated the entry
            if ((!cacheEntry.getKeys().containsKey(kid) || cacheEntry.getTimestamp() + updateTimeout <= currentTime)
                    && cacheEntry.getTimestamp() + minTimeBetweenRequests <= currentTime) {
                Map<String, RSAPublicKey> newJwks = getJwksFromUrl(url, sslContext, hostnameVerifier, connectionTimeout, readTimeout);
                if (newJwks == null) {
                    log.unableToFetchJwks(url.toString());
                    return null;
                }
                cacheEntry.setKeys(newJwks);
                cacheEntry.setTimestamp(currentTime);
            }
            return cacheEntry.getKeys();
        }
    }

    private static Map<String, RSAPublicKey> getJwksFromUrl(final URL url, SSLContext sslContext, HostnameVerifier hostnameVerifier, int connectionTimeout, int readTimeout) {
        JsonObject response = null;
        JsonReader jsonReader = null;
        try {
            URLConnection connection = url.openConnection();
            if (connection instanceof HttpsURLConnection) {
                HttpsURLConnection conn = (HttpsURLConnection) connection;
                conn.setRequestMethod("GET");
                conn.setSSLSocketFactory(sslContext.getSocketFactory());
                conn.setHostnameVerifier(hostnameVerifier);
                conn.setConnectTimeout(connectionTimeout);
                conn.setReadTimeout(readTimeout);
                conn.connect();
                InputStream inputStream = conn.getInputStream();
                jsonReader = Json.createReader(inputStream);
                response = jsonReader.readObject();
            }
        } catch (IOException e) {
            log.warn("Unable to connect to " + url.toString());
            return null;
        } finally {
            if (jsonReader != null) {
                jsonReader.close();
            }
        }

        if (response == null) {
            log.warn("No response when fetching jwk set from " + url.toString());
            return null;
        }
        JsonArray jwks = response.getJsonArray("keys");
        if (jwks == null) {
            log.warn("Unable to parse jwks");
            return null;
        }
        Map<String, RSAPublicKey> res = new LinkedHashMap<>();
        for (int i = 0; i < jwks.size(); i++) {
            JsonObject jwk = jwks.getJsonObject(i);
            String kid = jwk.getString("kid", null);
            String kty = jwk.getString("kty", null);
            String e1 = jwk.getString("e", null);
            String n1 = jwk.getString("n", null);

            if (kid == null) {
                log.tokenRealmJwkMissingClaim("kid");
                continue;
            }
            if (!"RSA".equals(kty)) {
                log.tokenRealmJwkMissingClaim("kty");
                continue;
            }
            if (e1 == null) {
                log.tokenRealmJwkMissingClaim("e");
                continue;
            }
            if (n1 == null) {
                log.tokenRealmJwkMissingClaim("n");
                continue;
            }

            BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(e1));
            BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(n1));
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(n, e);

            try {
                RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
                res.put(kid, publicKey);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
                log.info("Fetched jwk could not be parsed, ignoring...", ex);
            }
        }
        return res;
    }

    private static class CacheEntry {
        private Map<String, RSAPublicKey> keys;
        private long timestamp;

        public CacheEntry() {
            this.keys = Collections.emptyMap();
            this.timestamp = 0;
        }

        public Map<String, RSAPublicKey> getKeys() {
            return keys;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public void setKeys(Map<String, RSAPublicKey> keys) {
            this.keys = keys;
        }

        public void setTimestamp(long timestamp) {
            this.timestamp = timestamp;
        }
    }
}
