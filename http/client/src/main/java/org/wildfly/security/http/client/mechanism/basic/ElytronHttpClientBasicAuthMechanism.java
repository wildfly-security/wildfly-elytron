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

package org.wildfly.security.http.client.mechanism.basic;

import org.wildfly.security.http.client.utils.ElytronHttpClientConstants;
import org.wildfly.security.http.client.utils.ElytronHttpClientCredentialUtils;
import org.wildfly.security.http.client.utils.ElytronHttpClientRequestBuilder;

import java.net.http.HttpRequest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Elytron client for HTTP authentication
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
public class ElytronHttpClientBasicAuthMechanism {
    private static ElytronHttpClientCredentialUtils elytronHttpClientCredentialProvider = new ElytronHttpClientCredentialUtils();

    public static HttpRequest evaluateMechanism(HttpRequest httpRequest) {
        String userName = elytronHttpClientCredentialProvider.getUserName(httpRequest.uri());
        String password = elytronHttpClientCredentialProvider.getPassword(httpRequest.uri());

        Map<String, String > headers = new HashMap<>();
        headers.put(ElytronHttpClientConstants.AUTHORIZATION, basicAuth(userName, password));
        HttpRequest request = ElytronHttpClientRequestBuilder.buildRequest(httpRequest, headers);
        return request;
    }

    private static String basicAuth(String username, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
    }
}
