package org.wildfly.security.http.client.utils;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.Map;

public class ElytronHttpClientRequestBuilder {
    public static HttpRequest buildRequest(URI uri, String method, String body, Map<String, String> headers){
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(uri)
                .method(method, body != null ? HttpRequest.BodyPublishers.ofString(body) : HttpRequest.BodyPublishers.noBody());

        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                requestBuilder.header(entry.getKey(), entry.getValue());
            }
        }

        return requestBuilder.build();
    }
}
