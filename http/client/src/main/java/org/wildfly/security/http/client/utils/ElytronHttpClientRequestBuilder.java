package org.wildfly.security.http.client.utils;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.util.Map;

public class ElytronHttpClientRequestBuilder {
    public static HttpRequest buildRequest(HttpRequest httpRequest, Map<String, String> headers){
        String body = null;
        if(httpRequest.bodyPublisher() != null){
            body = httpRequest.bodyPublisher().toString();
        }
        String method = httpRequest.method();
        URI uri = httpRequest.uri();
        HttpHeaders httpHeaders = httpRequest.headers();

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(uri)
                .method(method, body != null ? HttpRequest.BodyPublishers.ofString(body) : HttpRequest.BodyPublishers.noBody());

        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                requestBuilder.header(entry.getKey(), entry.getValue());
            }
        }

        if (headers != null) {
            httpHeaders.map().forEach((headerName, headerValues) -> {
                if (headerValues != null && !headerValues.isEmpty()) {
                    for (String headerValue : headerValues) {
                        requestBuilder.header(headerName, headerValue);
                    }
                }
            });
        }

        return requestBuilder.build();
    }
}
