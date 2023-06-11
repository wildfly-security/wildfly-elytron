package org.wildfly.security.http.client.mechanism.bearer;

import org.wildfly.security.http.client.utils.ElytronHttpClientConstants;
import org.wildfly.security.http.client.utils.ElytronHttpClientCredentialUtils;
import org.wildfly.security.http.client.utils.ElytronHttpClientRequestBuilder;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.HashMap;
import java.util.Map;

public class ElytronHttpClientBearerAuthMechanism {

    public static HttpRequest evaluateMechanism(URI uri, String method, String body, Map<String, String> headers) {
        String token = ElytronHttpClientCredentialUtils.getToken(uri);
        if(headers == null){
            headers = new HashMap<>();
        }
        headers.put(ElytronHttpClientConstants.AUTHORIZATION, getBearerHeader(token));
        HttpRequest request = ElytronHttpClientRequestBuilder.buildRequest(uri, method, body, headers);
        return request;
    }

    private static String getBearerHeader(String token) {
        return "Bearer " + token;
    }
}
