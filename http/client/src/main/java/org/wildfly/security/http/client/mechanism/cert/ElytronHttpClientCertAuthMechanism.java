package org.wildfly.security.http.client.mechanism.cert;

import org.wildfly.security.http.client.utils.ElytronHttpClientCredentialUtils;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class ElytronHttpClientCertAuthMechanism {
    private static ElytronHttpClientCredentialUtils elytronHttpClientCredentialProvider = new ElytronHttpClientCredentialUtils();

    public static HttpRequest evaluateMechanism(URI uri){

        HttpRequest request = HttpRequest
                .newBuilder()
                .uri(uri)
                .POST(HttpRequest.BodyPublishers.ofString("Client Hello"))
                .build();
        return request;
    }
    public static HttpResponse evaluateRequest(URI uri) throws Exception{
        SSLContext sslContext = elytronHttpClientCredentialProvider.getSSLContext(uri);
        HttpRequest request = evaluateMechanism(uri);
        HttpClient httpClient = HttpClient.newBuilder()
                .sslContext(sslContext)
                .build();
        HttpResponse httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(httpResponse);
        return httpResponse;
    }
}
