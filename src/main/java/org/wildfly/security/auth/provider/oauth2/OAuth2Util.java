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

package org.wildfly.security.auth.provider.oauth2;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.CodePointIterator;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
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

/**
 * An utility class providing static methods to connect to standard OAuth2 HTTP endpoints.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class OAuth2Util {

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
    static JsonObject introspectAccessToken(URL tokenIntrospectionUrl, String clientId, String clientSecret, String token, SSLContext sslContext, HostnameVerifier hostnameVerifier) throws RealmUnavailableException {
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
                    ElytronMessages.log.errorf(ioe, "Unexpected response from token introspection endpoint [%s]. Response: [%s]", tokenIntrospectionUrl, response);
                } catch (IOException e) {
                    throw ElytronMessages.log.oauth2RealmTokenIntrospectionFailed(ioe);
                }
            } else {
                throw ElytronMessages.log.oauth2RealmTokenIntrospectionFailed(ioe);
            }
        } catch (Exception e) {
            throw ElytronMessages.log.oauth2RealmTokenIntrospectionFailed(e);
        }

        return null;
    }

    /**
     * Returns a {@link Attributes} instance based on the given {@link JsonObject}.
     *
     * @param claims a json object with the claims to extract
     * @return an {@link Attributes} instance with attributes from the given json object
     */
    static Attributes toAttributes(JsonObject claims) {
        return claims.entrySet().stream().reduce(new MapAttributes(), (mapAttributes, entry) -> {
            String claimName = entry.getKey();
            JsonValue claimValue = entry.getValue();

            if (JsonValue.ValueType.ARRAY.equals(claimValue.getValueType())) {
                JsonArray jsonArray = claims.getJsonArray(claimName);
                jsonArray.forEach(arrayValue -> mapAttributes.addLast(claimName, asString(arrayValue)));
            } else {
                mapAttributes.addLast(claimName, asString(claimValue));
            }

            return mapAttributes;
        }, (mapAttributes, mapAttributes2) -> mapAttributes);
    }

    private static String asString(JsonValue value) {
        if (JsonValue.ValueType.STRING.equals(value.getValueType())) {
            return ((JsonString) value).getString();
        }

        return value.toString();
    }

    private static HttpURLConnection openConnection(URL url, SSLContext sslContext, HostnameVerifier hostnameVerifier) throws IOException {
        Assert.checkNotNullParam("url", url);

        boolean isHttps = url.getProtocol().equalsIgnoreCase("https");

        if (isHttps) {
            if (sslContext == null) {
                throw ElytronMessages.log.oauth2RealmSSLContextNotSpecified(url);
            }

            if (hostnameVerifier == null) {
                throw ElytronMessages.log.oauth2RealmHostnameVerifierNotSpecified(url);
            }
        }

        try {
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            if (isHttps) {
                HttpsURLConnection https = (HttpsURLConnection) connection;

                https.setSSLSocketFactory(sslContext.getSocketFactory());
                https.setHostnameVerifier(hostnameVerifier);
            }

            return connection;
        } catch (IOException cause) {
            throw cause;
        }
    }

    private static byte[] buildParameters(Map<String, String> parameters) throws UnsupportedEncodingException {
        ByteStringBuilder params = new ByteStringBuilder();

        parameters.entrySet().stream().forEach(entry -> {
            if (params.length() > 0) {
                params.append('&');
            }
            params.append(entry.getKey()).append('=').append(entry.getValue());
        });

        return params.toArray();
    }
}
