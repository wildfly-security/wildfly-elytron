/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.http.oidc;

import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.wildfly.security.jose.jwks.JwksException;
import org.wildfly.security.jose.jwks.JwksFetcher;

/**
 * A {@link JwksFetcher} that delegates to a pre-built Apache {@link HttpClient}.
 *
 * <p>Used by {@link JWKPublicKeyLocator} and {@link JWKEncPublicKeyLocator} in the
 * OIDC module. Timeouts are baked into the {@code HttpClient} at construction time;
 * this fetcher adds no per-request timeout configuration.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
class ApacheHttpJwksFetcher implements JwksFetcher {

    private final HttpClient httpClient;
    private final Map<String, String> defaultHeaders;

    ApacheHttpJwksFetcher(HttpClient httpClient) {
        this(httpClient, Collections.emptyMap());
    }

    ApacheHttpJwksFetcher(HttpClient httpClient, Map<String, String> defaultHeaders) {
        this.httpClient = httpClient;
        this.defaultHeaders = defaultHeaders;
    }

    @Override
    public byte[] fetch(URL url) throws JwksException {
        HttpGet request = new HttpGet(url.toString());
        defaultHeaders.forEach(request::addHeader);
        try {
            HttpResponse response = httpClient.execute(request);
            int status = response.getStatusLine().getStatusCode();
            if (status != 200) {
                EntityUtils.consumeQuietly(response.getEntity());
                throw new JwksException("JWKS endpoint returned HTTP " + status + " for " + url);
            }
            if (response.getEntity() == null) {
                throw new JwksException("Empty response body from JWKS endpoint " + url);
            }
            return EntityUtils.toByteArray(response.getEntity());
        } catch (IOException e) {
            throw new JwksException("Failed to fetch JWKS from " + url, e);
        } finally {
            request.releaseConnection();
        }
    }
}
