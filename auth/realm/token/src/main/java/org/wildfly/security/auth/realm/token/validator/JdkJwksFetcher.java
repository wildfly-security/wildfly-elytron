/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
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

import org.wildfly.security.jose.jwks.JwksException;
import org.wildfly.security.jose.jwks.JwksFetcher;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

/**
 * A {@link JwksFetcher} that uses {@link HttpsURLConnection} to fetch JWKS documents.
 *
 * <p>Enforces HTTPS-only: throws {@link JwksException} if the URL scheme is not HTTPS.
 * Used by {@link JwtValidator} in the token-realm module.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
class JdkJwksFetcher implements JwksFetcher {

    private final SSLContext sslContext;
    private final HostnameVerifier hostnameVerifier;
    private final int connectionTimeoutMs;
    private final int readTimeoutMs;

    JdkJwksFetcher(SSLContext sslContext, HostnameVerifier hostnameVerifier,
                   int connectionTimeoutMs, int readTimeoutMs) {
        this.sslContext = sslContext;
        this.hostnameVerifier = hostnameVerifier;
        this.connectionTimeoutMs = connectionTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
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
            try (InputStream in = httpsConn.getInputStream()) {
                return in.readAllBytes();
            }
        } catch (IOException e) {
            throw new JwksException("Failed to fetch JWKS from " + url, e);
        } finally {
            httpsConn.disconnect();
        }
    }
}
