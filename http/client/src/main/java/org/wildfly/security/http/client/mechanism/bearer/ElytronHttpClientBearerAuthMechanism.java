package org.wildfly.security.http.client.mechanism.bearer;

import org.wildfly.security.http.client.utils.ElytronHttpClientConstants;
import org.wildfly.security.http.client.utils.ElytronHttpClientCredentialUtils;
import org.wildfly.security.http.client.utils.ElytronHttpClientRequestBuilder;

import java.net.http.HttpRequest;
import java.util.HashMap;
import java.util.Map;

public class ElytronHttpClientBearerAuthMechanism {

    public static HttpRequest evaluateMechanism(HttpRequest httpRequest) {
        String token = ElytronHttpClientCredentialUtils.getToken(httpRequest.uri());
        Map<String, String> headers = new HashMap<>();
        headers.put(ElytronHttpClientConstants.AUTHORIZATION, getBearerHeader(token));
        HttpRequest request = ElytronHttpClientRequestBuilder.buildRequest(httpRequest, headers);
        return request;
    }

    private static String getBearerHeader(String token) {
        return "Bearer " + token;
    }
}
