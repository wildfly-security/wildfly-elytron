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

import org.wildfly.security.http.client.utils.HttpMechClientConfigUtil;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;

/**
 * Elytron client for HTTP authentication
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
public class ElytronHttpClient {

    private final HttpClient client;
    private final  HttpMechClientConfigUtil httpMechClientConfigUtil;

    public ElytronHttpClient(){
        this.client = HttpClient.newHttpClient();
        this.httpMechClientConfigUtil = new HttpMechClientConfigUtil();
    }

    private static String basicAuth(String username, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
    }

    public HttpResponse<String> connect(String uri) throws Exception{
        HttpRequest request = getRequest(uri);
        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());

        return response;
    }

    public HttpRequest getRequest(String uri) throws Exception{
        String username = httpMechClientConfigUtil.getUsername(new URI(uri));
        String password = httpMechClientConfigUtil.getPassword(new URI(uri));
        String AuthType = httpMechClientConfigUtil.getHttpAuthenticationType(new URI(uri));
        String AuthHeader = null;
        if(AuthType.equalsIgnoreCase("basic")){
            AuthHeader = basicAuth(username,password);
        }
        HttpRequest request = HttpRequest
                .newBuilder()
                .uri(new URI(uri))
                .header("Authorization",AuthHeader)
                .build();

        return request;
    }
}