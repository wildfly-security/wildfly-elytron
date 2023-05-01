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
import org.wildfly.security.http.client.mechanism.ElytronHttpClientAuthMechanism;
import org.wildfly.security.http.client.mechanism.basic.ElytronHttpClientBasicAuthMechanism;
import org.wildfly.security.http.client.mechanism.digest.ElytronHttpClientDigestAuthMechanism;
import org.wildfly.security.http.client.utils.ElytronMessages;

import static org.wildfly.security.http.HttpConstants.OK;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
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

    private final HttpClient httpClient;
    private ElytronHttpClientAuthMechanism elytronHttpClientAuthMechanism;
    public ElytronHttpClient() {
        this.httpClient = HttpClient.newHttpClient();
    }

    private HttpResponse getResponse(HttpRequest request) throws IOException, InterruptedException{
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpRequest evaluateNoAuthMechanism(URI uri) {
        HttpRequest request = HttpRequest
                .newBuilder()
                .uri(uri)
                .build();

        return request;
    }

    /**
     * Used to connect to the secured uri and return the response based on that.
     */
    public HttpResponse connect(String uri) throws IOException, InterruptedException, URISyntaxException {

        URI uriPath = new URI(uri);
        HttpRequest request = evaluateNoAuthMechanism(uriPath);
        HttpResponse response = getResponse(request);

        if(response.statusCode() == OK){
            return response;
        }

        String authHeader = getAuthHeader(response);

        if(authHeader == null){
            throw new ElytronHttpClientException(ElytronMessages.log.responseHeaderExtractionFailed());
        }

        if (authHeader.toLowerCase().startsWith("basic")) {
            elytronHttpClientAuthMechanism = new ElytronHttpClientBasicAuthMechanism();
        } else if (authHeader.toLowerCase().startsWith("digest")) {
            elytronHttpClientAuthMechanism = new ElytronHttpClientDigestAuthMechanism(authHeader);
        }
        request = elytronHttpClientAuthMechanism.evaluateMechanism(uriPath);
        response = getResponse(request);
        return response;
    }

    private String getAuthHeader(HttpResponse response){
        String authHeader = null;
        Map<String, List<String>> allHeaderValues = response.headers().map();
        for(String headerKey : allHeaderValues.keySet()){
            if(headerKey.toLowerCase().equals("www-authenticate")){
                authHeader = allHeaderValues.get(headerKey).get(0);
            }
        }
        return authHeader;
    }
}