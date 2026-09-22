/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.auth.realm.token.validator;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;

import org.wildfly.security.jose.jwks.JwksException;
import org.wildfly.security.jose.jwks.JwksFetcher;

/**
 * A {@link JwksFetcher} that uses {@link HttpsURLConnection} to fetch JWKS documents.
 *
 * <p>Enforces HTTPS-only: throws {@link JwksException} if the URL scheme is not HTTPS. Also rejects any
 * non-200 response explicitly, and caps the response body size
 *
 * <p>Used by {@link JwtValidator} in the token-realm module.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
class JdkJwksFetcher implements JwksFetcher {

    static final long DEFAULT_MAX_RESPONSE_SIZE_BYTES = JwksFetcher.DEFAULT_MAX_RESPONSE_SIZE_BYTES;

    private final SSLContext sslContext;
    private final HostnameVerifier hostnameVerifier;
    private final int connectionTimeoutMs;
    private final int readTimeoutMs;
    private final long maxResponseSizeBytes;

    JdkJwksFetcher(SSLContext sslContext, HostnameVerifier hostnameVerifier,
                   int connectionTimeoutMs, int readTimeoutMs) {
        this(sslContext, hostnameVerifier, connectionTimeoutMs, readTimeoutMs, DEFAULT_MAX_RESPONSE_SIZE_BYTES);
    }

    JdkJwksFetcher(SSLContext sslContext, HostnameVerifier hostnameVerifier,
                   int connectionTimeoutMs, int readTimeoutMs, long maxResponseSizeBytes) {
        this.sslContext = sslContext;
        this.hostnameVerifier = hostnameVerifier;
        this.connectionTimeoutMs = connectionTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
        this.maxResponseSizeBytes = maxResponseSizeBytes;
    }

    @Override
    public byte[] fetch(URL url) throws JwksException {
        URLConnection connection;
        try {
            connection = url.openConnection();
        } catch (IOException e) {
            throw new JwksException("Failed to open connection to " + url, e);
        }
        if (!(connection instanceof HttpsURLConnection)) {
            throw new JwksException("JWKS endpoint must use HTTPS: " + url);
        }
        HttpsURLConnection httpsConn = (HttpsURLConnection) connection;
        httpsConn.setSSLSocketFactory(sslContext.getSocketFactory());
        httpsConn.setHostnameVerifier(hostnameVerifier);
        httpsConn.setConnectTimeout(connectionTimeoutMs);
        httpsConn.setReadTimeout(readTimeoutMs);
        try {
            httpsConn.setRequestMethod("GET");
            httpsConn.connect();
            int status = httpsConn.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                throw new JwksException("Endpoint returned HTTP " + status + " for " + url);
            }
            try (InputStream in = httpsConn.getInputStream()) {
                return readBounded(in, url, maxResponseSizeBytes);
            }
        } catch (IOException e) {
            throw new JwksException("Failed to fetch JWKS from " + url, e);
        } finally {
            httpsConn.disconnect();
        }
    }

    private static byte[] readBounded(InputStream in, URL url, long maxResponseSizeBytes) throws IOException, JwksException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        long total = 0;
        int bytesRead;
        while ((bytesRead = in.read(chunk)) != -1) {
            total += bytesRead;
            if (total > maxResponseSizeBytes) {
                throw new JwksException("Response from " + url + " exceeded the maximum allowed size of " + maxResponseSizeBytes + " bytes");
            }
            buffer.write(chunk, 0, bytesRead);
        }
        return buffer.toByteArray();
    }
}
