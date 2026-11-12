/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.http.oidc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Collections;
import java.util.Map;

import org.apache.http.HttpEntity;
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
    private final long maxResponseSizeBytes;

    ApacheHttpJwksFetcher(HttpClient httpClient) {
        this(httpClient, Collections.emptyMap());
    }

    ApacheHttpJwksFetcher(HttpClient httpClient, Map<String, String> defaultHeaders) {
        this(httpClient, defaultHeaders, DEFAULT_MAX_RESPONSE_SIZE_BYTES);
    }

    ApacheHttpJwksFetcher(HttpClient httpClient, Map<String, String> defaultHeaders, long maxResponseSizeBytes) {
        this.httpClient = httpClient;
        this.defaultHeaders = defaultHeaders;
        this.maxResponseSizeBytes = maxResponseSizeBytes;
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
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                throw new JwksException("Empty response body from JWKS endpoint " + url);
            }
            return readBounded(entity, url, maxResponseSizeBytes);
        } catch (IOException e) {
            throw new JwksException("Failed to fetch JWKS from " + url, e);
        } finally {
            request.releaseConnection();
        }
    }

    private static byte[] readBounded(HttpEntity entity, URL url, long maxResponseSizeBytes) throws IOException, JwksException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        long total = 0;
        try (InputStream in = entity.getContent()) {
            int bytesRead;
            while ((bytesRead = in.read(chunk)) != -1) {
                total += bytesRead;
                if (total > maxResponseSizeBytes) {
                    throw new JwksException("Response from " + url + " exceeded the maximum allowed size of " + maxResponseSizeBytes + " bytes");
                }
                buffer.write(chunk, 0, bytesRead);
            }
        }
        return buffer.toByteArray();
    }
}
