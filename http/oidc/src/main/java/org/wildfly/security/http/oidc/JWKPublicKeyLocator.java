/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

import static org.wildfly.security.http.oidc.ElytronMessages.log;

import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.http.client.methods.HttpGet;
import org.wildfly.security.jose.jwk.JWK;
import org.wildfly.security.jose.jwk.JsonWebKeySet;
import org.wildfly.security.jose.jwk.JsonWebKeySetUtil;

/**
 * A public key locator that dynamically obtains the public key from an OpenID
 * provider by sending a request to the provider's {@code jwks_uri} when needed.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class JWKPublicKeyLocator implements PublicKeyLocator {

    private Map<String, PublicKey> currentKeys = new ConcurrentHashMap<>();

    private volatile int lastRequestTime = 0;

    @Override
    public PublicKey getPublicKey(String kid, OidcClientConfiguration oidcClientConfiguration) {
        int minTimeBetweenRequests = oidcClientConfiguration.getMinTimeBetweenJwksRequests();
        int publicKeyCacheTtl = oidcClientConfiguration.getPublicKeyCacheTtl();
        int currentTime = getCurrentTime();

        // check if key is in cache
        PublicKey publicKey = lookupCachedKey(publicKeyCacheTtl, currentTime, kid);
        if (publicKey != null) {
            return publicKey;
        }

        // check if we are allowed to send request
        synchronized (this) {
            currentTime = getCurrentTime();
            if (currentTime > lastRequestTime + minTimeBetweenRequests) {
                sendRequest(oidcClientConfiguration);
                lastRequestTime = currentTime;
            } else {
                log.debug("Won't send request to jwks url. Last request time was " + lastRequestTime);
            }
            return lookupCachedKey(publicKeyCacheTtl, currentTime, kid);
        }
    }


    @Override
    public void reset(OidcClientConfiguration oidcClientConfiguration) {
        synchronized (this) {
            sendRequest(oidcClientConfiguration);
            lastRequestTime = getCurrentTime();
        }
    }


    private PublicKey lookupCachedKey(int publicKeyCacheTtl, int currentTime, String kid) {
        if (lastRequestTime + publicKeyCacheTtl > currentTime && kid != null) {
            return currentKeys.get(kid);
        } else {
            return null;
        }
    }


    private void sendRequest(OidcClientConfiguration oidcClientConfiguration) {
        if (log.isTraceEnabled()) {
            log.trace("Going to send request to retrieve new set of public keys for client " + oidcClientConfiguration.getResourceName());
        }

        HttpGet getMethod = new HttpGet(oidcClientConfiguration.getJwksUrl());
        try {
            JsonWebKeySet jwks = Oidc.sendJsonHttpRequest(oidcClientConfiguration, getMethod, JsonWebKeySet.class);

            Map<String, PublicKey> publicKeys = JsonWebKeySetUtil.getKeysForUse(jwks, JWK.Use.SIG);

            if (log.isDebugEnabled()) {
                log.debug("Public keys successfully retrieved for client " +  oidcClientConfiguration.getResourceName() + ". New kids: " + publicKeys.keySet().toString());
            }

            // update current keys
            currentKeys.clear();
            currentKeys.putAll(publicKeys);

        } catch (OidcException e) {
            log.error("Error when sending request to retrieve public keys", e);
        }
    }

    private static int getCurrentTime() {
        return (int) (System.currentTimeMillis() / 1000);
    }

}
