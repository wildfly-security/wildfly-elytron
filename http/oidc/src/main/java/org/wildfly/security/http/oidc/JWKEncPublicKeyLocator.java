/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.JSON_CONTENT_TYPE;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Map;
import java.util.List;

import org.apache.http.client.methods.HttpGet;
import org.wildfly.security.jose.jwk.JWK;
import org.wildfly.security.jose.jwk.JsonWebKeySet;
import org.wildfly.security.jose.jwk.JsonWebKeySetUtil;

/**
 * A public key locator that dynamically obtains the public key used for encryption
 * from an OpenID provider by sending a request to the provider's {@code jwks_uri}
 * when needed.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 * */
class JWKEncPublicKeyLocator implements PublicKeyLocator {
    private List<PublicKey> currentKeys = new ArrayList<>();

    private volatile int lastRequestTime = 0;

    @Override
    public PublicKey getPublicKey(String kid, OidcClientConfiguration config) {
        int minTimeBetweenRequests = config.getMinTimeBetweenJwksRequests();
        int publicKeyCacheTtl = config.getPublicKeyCacheTtl();
        int currentTime = getCurrentTime();

        PublicKey publicKey = lookupCachedKey(publicKeyCacheTtl, currentTime);
        if (publicKey != null) {
            return publicKey;
        }

        synchronized (this) {
            currentTime = getCurrentTime();
            if (currentTime > lastRequestTime + minTimeBetweenRequests) {
                sendRequest(config);
                lastRequestTime = currentTime;
            } else {
                log.debug("Won't send request to jwks url. Last request time was " + lastRequestTime);
            }
            return lookupCachedKey(publicKeyCacheTtl, currentTime);
        }

    }

    @Override
    public void reset(OidcClientConfiguration config) {
        synchronized (this) {
            sendRequest(config);
            lastRequestTime = getCurrentTime();
        }
    }

    private PublicKey lookupCachedKey(int publicKeyCacheTtl, int currentTime) {
        if (lastRequestTime + publicKeyCacheTtl > currentTime) {
            return currentKeys.get(0); // returns the first cached public key
        } else {
            return null;
        }
    }

    private static int getCurrentTime() {
        return (int) (System.currentTimeMillis() / 1000);
    }

    private void sendRequest(OidcClientConfiguration config) {
        if (log.isTraceEnabled()) {
            log.trace("Going to send request to retrieve new set of public keys to encrypt a JWT request for client " + config.getResourceName());
        }

        HttpGet request = new HttpGet(config.getJwksUrl());
        request.addHeader(ACCEPT, JSON_CONTENT_TYPE);
        try {
            JsonWebKeySet jwks = Oidc.sendJsonHttpRequest(config, request, JsonWebKeySet.class);
            Map<String, PublicKey> publicKeys = JsonWebKeySetUtil.getKeysForUse(jwks, JWK.Use.ENC);

            if (log.isDebugEnabled()) {
                log.debug("Public keys successfully retrieved for client " +  config.getResourceName() + ". New kids: " + publicKeys.keySet());
            }

            // update current keys
            currentKeys.clear();
            currentKeys.addAll(publicKeys.values());
        } catch (OidcException e) {
            log.error("Error when sending request to retrieve public keys", e);
        }
    }
}
