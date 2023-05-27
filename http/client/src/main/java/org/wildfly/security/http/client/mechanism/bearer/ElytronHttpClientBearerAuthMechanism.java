package org.wildfly.security.http.client.mechanism.bearer;

import org.wildfly.security.http.client.utils.ElytronHttpClientCredentialUtils;

import java.net.URI;
import java.net.http.HttpRequest;

public class ElytronHttpClientBearerAuthMechanism {

    private static final String AUTHORIZATION = "Authorization";
    private static ElytronHttpClientCredentialUtils elytronHttpClientCredentialProvider = new ElytronHttpClientCredentialUtils();

    public static HttpRequest evaluateMechanism(URI uri) {
        String token = elytronHttpClientCredentialProvider.getToken(uri);
        HttpRequest request = HttpRequest
                .newBuilder()
                .uri(uri)
                .header(AUTHORIZATION, getBearerHeader(token))
                .build();
        return request;
    }

    private static String getBearerHeader(String token){
        return "Bearer " + token;
    }
}
