/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.realm.token.TokenValidator;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.evidence.BearerTokenEvidence;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.util.JsonUtil.toAttributes;

/**
 * A RFC-7662 (OAuth2 Token Introspection) compliant {@link TokenValidator}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OAuth2IntrospectValidator implements TokenValidator {

    /**
     * Returns a {@link Builder} instance that can be used to configure and create a {@link OAuth2IntrospectValidator}.
     *
     * @return the {@link Builder}
     */
    public static Builder builder() {
        return new Builder();
    }

    private final URL tokenIntrospectionUrl;
    private final String clientId;
    private final String clientSecret;
    private final SSLContext sslContext;
    private final HostnameVerifier hostnameVerifier;

    OAuth2IntrospectValidator(Builder configuration) {
        this.tokenIntrospectionUrl = Assert.checkNotNullParam("tokenIntrospectionUrl", configuration.tokenIntrospectionUrl);
        this.clientId = Assert.checkNotNullParam("clientId", configuration.clientId);
        this.clientSecret = Assert.checkNotNullParam("clientSecret", configuration.clientSecret);

        if (tokenIntrospectionUrl.getProtocol().equalsIgnoreCase("https")) {
            Assert.checkNotNullParam("sslContext", configuration.sslContext);
        }

        this.sslContext = configuration.sslContext;
        this.hostnameVerifier = configuration.hostnameVerifier;
    }

    @Override
    public Attributes validate(BearerTokenEvidence evidence) throws RealmUnavailableException {
        Assert.checkNotNullParam("evidence", evidence);

        try {
            JsonObject claims = introspectAccessToken(this.tokenIntrospectionUrl,
                    this.clientId, this.clientSecret, evidence.getToken(), this.sslContext, this.hostnameVerifier);

            if (isValidToken(claims)) {
                return toAttributes(claims);
            }
        } catch (Exception e) {
            throw log.tokenRealmOAuth2TokenIntrospectionFailed(e);
        }

        return null;
    }

    private boolean isValidToken(JsonObject claims) {
        return claims != null && claims.getBoolean("active", false);
    }

    /**
     * Introspects an OAuth2 Access Token using a RFC-7662 compatible endpoint.
     *
     * @param tokenIntrospectionUrl an {@link URL} pointing to a RFC-7662 compatible endpoint
     * @param clientId the identifier of a client within the OAUth2 Authorization Server
     * @param clientSecret the secret of the client
     * @param token the access token to introspect
     * @param sslContext the ssl context
     * @param hostnameVerifier the hostname verifier
     * @return a @{JsonObject} representing the response from the introspection endpoint or null if
     */
    private JsonObject introspectAccessToken(URL tokenIntrospectionUrl, String clientId, String clientSecret, String token, SSLContext sslContext, HostnameVerifier hostnameVerifier) throws RealmUnavailableException {
        Assert.checkNotNullParam("clientId", clientId);
        Assert.checkNotNullParam("clientSecret", clientSecret);
        Assert.checkNotNullParam("token", token);

        HttpURLConnection connection = null;

        try {
            connection = openConnection(tokenIntrospectionUrl, sslContext, hostnameVerifier);

            HashMap<String, String> parameters = new HashMap<>();

            parameters.put("token", token);
            parameters.put("token_type_hint", "access_token");

            byte[] params = buildParameters(parameters);

            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setRequestProperty("Content-Length", String.valueOf(params.length));
            connection.setRequestProperty("Authorization", "Basic " + CodePointIterator.ofString(clientId + ":" + clientSecret).asUtf8().base64Encode().drainToString());

            try (OutputStream outputStream = connection.getOutputStream()) {
                outputStream.write(params);
            }

            try (InputStream inputStream = new BufferedInputStream(connection.getInputStream())) {
                return Json.createReader(inputStream).readObject();
            }
        } catch (IOException ioe) {
            if (connection != null && connection.getErrorStream() != null) {
                InputStream errorStream = connection.getErrorStream();

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(errorStream))) {
                    StringBuffer response = reader.lines().reduce(new StringBuffer(), StringBuffer::append, (buffer1, buffer2) -> buffer1);
                    log.errorf(ioe, "Unexpected response from token introspection endpoint [%s]. Response: [%s]", tokenIntrospectionUrl, response);
                } catch (IOException e) {
                    throw log.tokenRealmOAuth2TokenIntrospectionFailed(ioe);
                }
            } else {
                throw log.tokenRealmOAuth2TokenIntrospectionFailed(ioe);
            }
        } catch (Exception e) {
            throw log.tokenRealmOAuth2TokenIntrospectionFailed(e);
        }

        return null;
    }

    private HttpURLConnection openConnection(URL url, SSLContext sslContext, HostnameVerifier hostnameVerifier) throws IOException {
        Assert.checkNotNullParam("url", url);

        boolean isHttps = url.getProtocol().equalsIgnoreCase("https");

        try {
            log.debugf("Opening connection to token introspection endpoint [%s]", url);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            if (isHttps) {
                HttpsURLConnection https = (HttpsURLConnection) connection;

                https.setSSLSocketFactory(sslContext.getSocketFactory());

                if (hostnameVerifier != null) {
                    https.setHostnameVerifier(hostnameVerifier);
                }
            }

            return connection;
        } catch (IOException cause) {
            throw cause;
        }
    }

    private byte[] buildParameters(Map<String, String> parameters) throws UnsupportedEncodingException {
        ByteStringBuilder params = new ByteStringBuilder();

        parameters.entrySet().stream().forEach(entry -> {
            if (params.length() > 0) {
                params.append('&');
            }
            params.append(entry.getKey()).append('=').append(entry.getValue());
        });

        return params.toArray();
    }

    public static class Builder {

        private String clientId;
        private String clientSecret;
        private URL tokenIntrospectionUrl;
        private SSLContext sslContext;
        private HostnameVerifier hostnameVerifier;

        private Builder() {
        }

        /**
         * An {@link URL} pointing to a RFC-7662 OAuth2 Token Introspection compatible endpoint.
         *
         * @param url the token introspection endpoint
         * @return this instance
         */
        public Builder tokenIntrospectionUrl(URL url) {
            this.tokenIntrospectionUrl = url;
            return this;
        }

        /**
         * <p>The identifier of a client registered within the OAuth2 Authorization Server that will be used to authenticate this server
         * in order to validate bearer tokens arriving to this server.
         *
         * <p>Please note that the client will be usually a confidential client with both an identifier and secret configured in order to
         * authenticate against the token introspection endpoint. In this case, the endpoint must support HTTP BASIC authentication using
         * the client credentials (both id and secret).
         *
         * @param clientId the identifier of a client within the OAUth2 Authorization Server
         * @return this instance
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * The secret of the client identified by the given {@link #clientId}.
         *
         * @param clientSecret the secret of the client
         * @return this instance
         */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * <p>A predefined {@link SSLContext} that will be used to connect to the token introspection endpoint when using SSL/TLS. This configuration is mandatory
         * if the given token introspection url is using SSL/TLS.
         *
         * @param sslContext the SSL context
         * @return this instance
         */
        public Builder useSslContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        /**
         * A {@link HostnameVerifier} that will be used to validate the hostname when using SSL/TLS. This configuration is mandatory
         * if the given token introspection url is using SSL/TLS.
         *
         * @param hostnameVerifier the hostname verifier
         * @return this instance
         */
        public Builder useSslHostnameVerifier(HostnameVerifier hostnameVerifier) {
            this.hostnameVerifier = hostnameVerifier;
            return this;
        }

        /**
         * Returns a {@link OAuth2IntrospectValidator} instance based on all the configuration provided with this builder.
         *
         * @return a new {@link OAuth2IntrospectValidator} instance with all the given configuration
         */
        public OAuth2IntrospectValidator build() {
            return new OAuth2IntrospectValidator(this);
        }
    }
}
