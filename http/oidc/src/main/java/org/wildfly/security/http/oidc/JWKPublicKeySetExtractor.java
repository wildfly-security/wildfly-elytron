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

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.wildfly.security.http.oidc.Oidc.JSON_CONTENT_TYPE;

import java.io.IOException;
import org.apache.http.client.methods.HttpGet;
import org.jose4j.lang.JoseException;
import org.wildfly.security.jose.jwk.JsonWebKeySet;
/**
 * A public key locator that dynamically obtains the public key from an OpenID
 * provider by sending a request to the provider's {@code jwks_uri} when needed.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 * */
public class JWKPublicKeySetExtractor implements OidcPublicKeyExtractor {
    public JWKPublicKeySetExtractor() {
    }
    @Override
    public JsonWebKeySet extractPublicKeySet(OidcClientConfiguration config) throws IOException, JoseException {
        HttpGet request = new HttpGet(config.getJwksUrl());
        request.addHeader(ACCEPT, JSON_CONTENT_TYPE);
        return Oidc.sendJsonHttpRequest(config, request, JsonWebKeySet.class);
    }

}
