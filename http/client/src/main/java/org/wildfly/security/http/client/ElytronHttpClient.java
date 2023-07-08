/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.http.client;

import org.wildfly.security.http.client.exception.ElytronHttpClientException;
import org.wildfly.security.http.client.mechanism.basic.ElytronHttpClientBasicAuthMechanism;
import org.wildfly.security.http.client.mechanism.bearer.ElytronHttpClientBearerAuthMechanism;
import org.wildfly.security.http.client.mechanism.digest.ElytronHttpClientDigestAuthMechanism;
import org.wildfly.security.http.client.utils.ElytronHttpClientCredentialUtils;
import org.wildfly.security.http.client.utils.ElytronMessages;

import javax.net.ssl.SSLContext;

import static org.wildfly.security.http.HttpConstants.OK;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

/**
 * Elytron client for HTTP authentication
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
public class ElytronHttpClient {

    private HttpClient httpClient;

    public ElytronHttpClient() {
        this.httpClient = HttpClient.newHttpClient();
    }

    /**
     * Used to connect to the secured uri and return the response based on that.
     */
    public HttpResponse connect(HttpRequest httpRequest) throws IOException, InterruptedException, URISyntaxException {
        addSSLContextToHttpClient(httpRequest.uri());

        HttpResponse response = getResponse(httpRequest);
        if (response.statusCode() == OK) {
            return response;
        }

        String authenticateHeader = getAuthenticateHeader(response);
        if (authenticateHeader == null) {
            throw new ElytronHttpClientException(ElytronMessages.log.responseHeaderExtractionFailed());
        }
        HttpRequest authRequest = null;

        String challenge = getFirstChallenge(authenticateHeader);
        String mechanismType = getMechanismType(challenge);

        switch (mechanismType) {
            case "basic":
                authRequest = ElytronHttpClientBasicAuthMechanism.evaluateMechanism(httpRequest);
                break;
            case "digest":
                authRequest = ElytronHttpClientDigestAuthMechanism.evaluateMechanism(authenticateHeader, httpRequest);
                break;
            case "bearer":
                authRequest = ElytronHttpClientBearerAuthMechanism.evaluateMechanism(httpRequest);
                break;
        }

        if (authRequest != null) {
            response = getResponse(authRequest);
        }
        return response;
    }

    public HttpResponse connect(String uri) throws URISyntaxException, IOException, InterruptedException {
        URI uriPath = new URI(uri);
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(uriPath)
                .build();
        return connect(httpRequest);
    }
    private HttpResponse getResponse(HttpRequest request) throws IOException, InterruptedException {
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private void addSSLContextToHttpClient(URI uri) throws MalformedURLException {
        String protocol = new URL(uri.toString()).getProtocol();

        if (protocol.equalsIgnoreCase("https")) {
            SSLContext sslContext = ElytronHttpClientCredentialUtils.getSSLContext(uri);
            httpClient = HttpClient.newBuilder().sslContext(sslContext).build();
        }
    }

    private String getFirstChallenge(String authHeader){
        String[] authChallenges = authHeader.split(",");
        String challenge = authChallenges[0];
        return challenge;
    }

    private String getAuthenticateHeader(HttpResponse response) {
        String authHeader = null;
        Map<String, List<String>> allHeaderValues = response.headers().map();
        for (String headerKey : allHeaderValues.keySet()) {
            if (headerKey.toLowerCase().equals("www-authenticate")) {
                authHeader = allHeaderValues.get(headerKey).get(0);
            }
        }
        return authHeader;
    }

    private String getMechanismType(String challenge) {
        return challenge.trim().split(" ")[0].toLowerCase();
    }
}