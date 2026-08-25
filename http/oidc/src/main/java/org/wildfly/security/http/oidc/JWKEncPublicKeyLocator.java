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

import static org.wildfly.security.jose.jwk.JsonWebKeySetUtil.FOR_ENCRYPTION;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.PublicKey;
import java.util.Map;

import org.wildfly.security.jose.jwks.JwksCache;
import org.wildfly.security.jose.jwks.JwksConfig;

/**
 * A public key locator that dynamically obtains the public key used for encryption
 * from an OpenID provider by sending a request to the provider's {@code jwks_uri}
 * when needed.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 * */
class JWKEncPublicKeyLocator implements PublicKeyLocator {

    private volatile JwksCache jwksCache;

    @Override
    public PublicKey getPublicKey(String kid, OidcClientConfiguration config) {
        URL jwksUrl = resolveJwksUrl(config);
        if (jwksUrl == null) {
            return null;
        }
        return ensureInitialized(config).getAnyKey(jwksUrl);
    }

    @Override
    public void reset(OidcClientConfiguration config) {
        URL jwksUrl = resolveJwksUrl(config);
        if (jwksUrl == null) {
            return;
        }
        ensureInitialized(config).reset(jwksUrl);
    }

    private JwksCache ensureInitialized(OidcClientConfiguration config) {
        JwksCache cache = jwksCache;
        if (cache == null) {
            synchronized (this) {
                cache = jwksCache;
                if (cache == null) {
                    cache = new JwksCache(JwksConfig.builder()
                            .fetcher(new ApacheHttpJwksFetcher(config.getClient(),
                                    Map.of("Accept", "application/json")))
                            .keyFilter(FOR_ENCRYPTION)
                            .cacheTtlMs(config.getPublicKeyCacheTtl() * 1000L)
                            .minTimeBetweenRequestsMs(config.getMinTimeBetweenJwksRequests() * 1000L)
                            .preserveStaleOnFailure(true)
                            .build());
                    jwksCache = cache;
                }
            }
        }
        return cache;
    }

    private static URL resolveJwksUrl(OidcClientConfiguration config) {
        String jwksUrlString = config.getJwksUrl();
        if (jwksUrlString == null) {
            return null;
        }
        try {
            return new URL(jwksUrlString);
        } catch (MalformedURLException e) {
            throw new RuntimeException("Invalid JWKS URL: " + jwksUrlString, e);
        }
    }
}
