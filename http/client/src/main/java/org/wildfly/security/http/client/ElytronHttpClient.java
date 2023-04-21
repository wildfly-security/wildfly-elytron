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
import org.wildfly.security.http.client.utils.DigestHttpMechanismUtil;
import org.wildfly.security.http.client.utils.HttpMechClientConfigUtil;
import org.wildfly.security.http.client.utils.ElytronMessages;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Elytron client for HTTP authentication
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
public class ElytronHttpClient {

    private static final String AUTHORIZATION = "Authorization";
    private final HttpClient client;
    private final HttpMechClientConfigUtil httpMechClientConfigUtil;
    private String lastURI;
    private Map<String, String> authParams;
    private String userName;
    private String password;
    private String previousMechanism;
    private DigestHttpMechanismUtil digestHttpMechanismUtil;

    public ElytronHttpClient() {
        this.client = HttpClient.newHttpClient();
        this.httpMechClientConfigUtil = new HttpMechClientConfigUtil();
        authParams = new HashMap<>();
        previousMechanism = null;
        lastURI = null;
        digestHttpMechanismUtil = new DigestHttpMechanismUtil();
    }

    private static String basicAuth(String username, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
    }

    public HttpResponse evaluateDigestMechanism(String uri) throws Exception {

        HttpRequest request;
        request = digestHttpMechanismUtil.createDigestRequest(uri,userName,password,authParams);

        if(lastURI==null || !(lastURI.equals(uri))){
            lastURI = uri;
        }

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 401) {
            String authHeader = response.headers().allValues("www-authenticate").get(0);
            digestHttpMechanismUtil.updateAuthParams(authHeader,authParams);
            request = digestHttpMechanismUtil.createDigestRequest(uri,userName,password,authParams);
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        }
        return response;
    }

    //To test header values from ElytronHttpClientTest
    public HttpRequest getResponseHeader(String responseHeader, String uri) throws Exception {

        digestHttpMechanismUtil.updateAuthParams(responseHeader,authParams);

        String realm = authParams.get("realm");
        String nonce = authParams.get("nonce");
        String opaque = authParams.get("opaque");
        String algorithm = authParams.get("algorithm");
        String qop = authParams.get("qop");

        String path = digestHttpMechanismUtil.getUriPath(uri);

        userName = httpMechClientConfigUtil.getUsername(new URI(uri));
        password = httpMechClientConfigUtil.getPassword(new URI(uri));

        String response;
        if (qop == null) {
            response = digestHttpMechanismUtil.computeDigestWithoutQop(path, nonce, userName, password, algorithm, realm, "GET");
        } else {
            response = digestHttpMechanismUtil.computeDigestWithQop(path, nonce, "0a4f113b", "00000001", userName, password, algorithm, realm, qop, "GET");
        }

        HttpRequest request2 = HttpRequest
                .newBuilder()
                .uri(new URI(uri))
                .header(AUTHORIZATION, "Digest " +
                        "username=\"" + userName + "\", " +
                        "realm=\"" + realm + "\"," +
                        "nonce=\"" + nonce + "\", " +
                        "uri=\"" + path + "\", " +
                        "qop=\"" + qop + "\", " +
                        "nc=00000001, " +
                        "cnonce=\"0a4f113b\", " +
                        "response=\"" + response + "\", " +
                        "opaque=\"" + opaque + "\", " +
                        "algorithm=" + algorithm)
                .build();
        return request2;

    }

    public HttpRequest getRequest(String uri) throws Exception {
        String username = httpMechClientConfigUtil.getUsername(new URI(uri));
        String password = httpMechClientConfigUtil.getPassword(new URI(uri));
        String AuthType = httpMechClientConfigUtil.getHttpAuthenticationType(new URI(uri));
        String AuthHeader = null;
        if (AuthType.equalsIgnoreCase("basic")) {
            AuthHeader = basicAuth(username, password);
        }
        HttpRequest request = HttpRequest
                .newBuilder()
                .uri(new URI(uri))
                .header(AUTHORIZATION, AuthHeader)
                .build();

        return request;
    }

    public HttpResponse evaluateBasicMechanism(String uri) throws Exception {
        HttpRequest request = HttpRequest
                .newBuilder()
                .uri(new URI(uri))
                .header(AUTHORIZATION, basicAuth(userName, password))
                .build();
        HttpResponse response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response;
    }
    public HttpResponse evaluateNoAuthMechanism(String uri) throws Exception{
        HttpRequest request = HttpRequest
                .newBuilder()
                .uri(new URI(uri))
                .build();

        HttpResponse response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response;
    }

    public HttpResponse connect(String uri) throws Exception {
        userName = httpMechClientConfigUtil.getUsername(new URI(uri));
        password = httpMechClientConfigUtil.getPassword(new URI(uri));
        HttpResponse response = null;

        if (lastURI != null && lastURI.equals(uri)) {
            switch (previousMechanism) {
                case "basic":
                    response = evaluateBasicMechanism(uri);
                    break;
                case "digest":
                    response = evaluateDigestMechanism(uri);
                    break;
                case "noauth":
                    response = evaluateNoAuthMechanism(uri);
                    break;
            }
        } else {
            response = evaluateNoAuthMechanism(uri);

            if(response.statusCode()==200){
                previousMechanism = "noauth";
                lastURI = uri;
                return response;
            }
            String authHeader = null;
            Map<String, List<String>> allHeaderValues = response.headers().map();
            for(String headerKey : allHeaderValues.keySet()){
                if(headerKey.toLowerCase().equals("www-authenticate")){
                    authHeader = allHeaderValues.get(headerKey).get(0);
                }
            }

            if(authHeader == null){
                throw new ElytronHttpClientException(ElytronMessages.log.responseHeaderExtractionFailed());
            }

            if (authHeader.toLowerCase().startsWith("basic")) {
                response = evaluateBasicMechanism(uri);
                previousMechanism = "basic";
            } else if (authHeader.toLowerCase().startsWith("digest")) {
                digestHttpMechanismUtil.updateAuthParams(authHeader,authParams);
                response = evaluateDigestMechanism(uri);
                previousMechanism = "digest";
            }
        }
        return response;
    }

}