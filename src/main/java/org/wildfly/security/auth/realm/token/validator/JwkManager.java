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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * Object for caching RSA JSON Web Keys for signature validation
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
class JwkManager {

    private final Map<URL, Map<String, RSAPublicKey>> keys = new LinkedHashMap<>();
    private final Map<URL, Long> timeouts = new ConcurrentHashMap<>();
    private final SSLContext sslContext;
    private final HostnameVerifier hostnameVerifier;

    private final long updateTimeout;

    private static final int CONNECTION_TIMEOUT = 2000;//2s

    JwkManager(SSLContext sslContext, HostnameVerifier hostnameVerifier, long updateTimeout) {
        this.sslContext = sslContext;
        this.hostnameVerifier = hostnameVerifier;
        this.updateTimeout = updateTimeout;
    }

    /**
     * Thread-safe method for receiving remote public key
     * @param kid key id
     * @param url remote jkws url
     * @return signature verification public key if found, null otherwise
     */
    public PublicKey getPublicKey(String kid, URL url) {
        Map<String, RSAPublicKey> urlKeys = checkRemote(url);

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

    private Map<String, RSAPublicKey> checkRemote(URL url) {
        Assert.checkNotNullParam("url", url);

        long lastUpdate = 0;

        Map<String, RSAPublicKey> urlKeys;

        synchronized (keys) {
            urlKeys = keys.get(url);
            if (urlKeys == null) {
                urlKeys = new ConcurrentHashMap<>();
                keys.put(url, urlKeys);
            }
        }

        synchronized (urlKeys) {
            if (timeouts.containsKey(url)) {
                lastUpdate = timeouts.get(url);
            }

            if (lastUpdate + updateTimeout <= System.currentTimeMillis()) {
                Map<String, RSAPublicKey> newJwks = getJwksFromUrl(url, sslContext, hostnameVerifier);
                if (newJwks == null) {
                    log.unableToFetchJwks(url.toString());
                    return null;
                }
                urlKeys.clear();
                urlKeys.putAll(newJwks);
                timeouts.put(url, System.currentTimeMillis());
            }
            return urlKeys;
        }
    }

    private static Map<String, RSAPublicKey> getJwksFromUrl(final URL url, SSLContext sslContext, HostnameVerifier hostnameVerifier) {
        JsonObject response = null;
        try {
            URLConnection connection = url.openConnection();
            if (connection instanceof HttpsURLConnection) {
                HttpsURLConnection conn = (HttpsURLConnection) connection;
                conn.setRequestMethod("GET");
                conn.setSSLSocketFactory(sslContext.getSocketFactory());
                conn.setHostnameVerifier(hostnameVerifier);
                conn.setConnectTimeout(CONNECTION_TIMEOUT);
                conn.setReadTimeout(CONNECTION_TIMEOUT);
                conn.connect();
                InputStream inputStream = conn.getInputStream();
                response = Json.createReader(inputStream).readObject();
            }
        } catch (IOException e) {
            log.warn("Unable to connect to " + url.toString());
            return null;
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

            BigInteger e = new BigInteger(Base64.getDecoder().decode(e1));
            BigInteger n = new BigInteger(Base64.getDecoder().decode(n1));
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(n, e);

            try {
                RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
                res.put(kid, publicKey);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
                log.info("Fetched jwk could not be parsed, ignoring...");
                ex.printStackTrace();
                continue;
            }
        }
        return res;
    }
}