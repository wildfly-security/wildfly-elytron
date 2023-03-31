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
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Elytron client for HTTP authentication
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
public class ElytronHttpClient {

    private final HttpClient client;
    private final HttpMechClientConfigUtil httpMechClientConfigUtil;
    private String lastURI;
    private Map<String, String> authParams;
    private String userName;
    private String password;
    private String previousMechanism;

    public ElytronHttpClient() {
        this.client = HttpClient.newHttpClient();
        this.httpMechClientConfigUtil = new HttpMechClientConfigUtil();
        authParams = new HashMap<>();
        previousMechanism = null;
        lastURI = null;
    }

    private static String basicAuth(String username, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
    }

    public HttpResponse evaluateDigestMechanism(String uri) throws Exception {

        HttpRequest request;
        request = createDigestRequest(uri);

        if(lastURI==null || !(lastURI.equals(uri))){
            lastURI = uri;
        }

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 401) {
            String authHeader = response.headers().allValues("www-authenticate").get(0);
            updateAuthParams(authHeader);
            request = createDigestRequest(uri);
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        }
        return response;
    }

    //To test header values from ElytronHttpClientTest
    public HttpRequest getResponseHeader(String responseHeader) throws Exception {

        updateAuthParams(responseHeader);
        String realm = authParams.get("realm");
        String nonce = authParams.get("nonce");
        String opaque = authParams.get("opaque");
        String algorithm = authParams.get("algorithm");
        String qop = authParams.get("qop");

        String path = "/test";
        String uri = "http://localhost:8080" + path;

        userName = httpMechClientConfigUtil.getUsername(new URI(uri));
        password = httpMechClientConfigUtil.getPassword(new URI(uri));

        String resp;
        if (qop == null) {
            resp = computeDigestWithoutQop(path, nonce, userName, password, algorithm, realm, "GET");
        } else {
            resp = computeDigestWithQop(path, nonce, "0a4f113b", "00000001", userName, password, algorithm, realm, qop, "GET");
        }

        HttpRequest request2 = HttpRequest
                .newBuilder()
                .uri(new URI(uri))
                .header("Authorization", "Digest " +
                        "username=\"" + userName + "\", " +
                        "realm=\"" + realm + "\"," +
                        "nonce=\"" + nonce + "\", " +
                        "uri=\"" + path + "\", " +
                        "qop=\"" + qop + "\", " +
                        "nc=00000001, " +
                        "cnonce=\"" + generateCNonce() +"\", " +
                        "response=\"" + resp + "\", " +
                        "opaque=\"" + opaque + "\", " +
                        "algorithm=" + algorithm)
                .build();
        return request2;

    }

    private void updateAuthParams(String authHeader) {
        Pattern pattern = Pattern.compile("(\\w+)=([^,\\s]+)");
        Matcher matcher = pattern.matcher(authHeader);

                        "realm=\"" + realm + "\"," +
                        "nonce=\"" + nonce + "\", " +
                        "uri=\"" + uriPath + "\", " +
                        "qop=\"" + qop + "\", " +
                        "nc=\"" + ncount + "\"," +
                        "cnonce=\"" + cnonce + "\", " +
                        "response=\"" + resp + "\", " +
                        "opaque=\"" + opaque + "\", " +
                        "algorithm=" + algorithm)
                .build();
        int updateNonceCount = Integer.parseInt(authParams.getOrDefault("ncount", "0")) + 1;
        authParams.put("ncount", String.valueOf(updateNonceCount));
        return request;
    }

    private static String computeDigestWithoutQop(String uri, String nonce, String username, String
            password, String algorithm, String realm, String method) throws NoSuchAlgorithmException {
        String A1, HashA1, A2, HashA2;
        MessageDigest md = MessageDigest.getInstance(algorithm);
        A1 = username + ":" + realm + ":" + password;
        HashA1 = calculateMD5(A1);
        A2 = method + ":" + uri;
        HashA2 = calculateMD5(A2);
        String combo, finalHash;
        combo = HashA1 + ":" + nonce + ":" + HashA2;
        finalHash = calculateMD5(combo);
        return finalHash;
    }

    private static String computeDigestWithQop(String uri, String nonce, String cnonce, String nc, String
            username, String password, String algorithm, String realm, String qop, String method) throws
            NoSuchAlgorithmException {

        System.out.println("uri : " + uri + " nonce " + nonce + " cnonce " + cnonce + " nc " + nc + " username " + username + " password " + password + " realm " + realm + " qop " + qop + " method " + method);
        String A1, HashA1, A2, HashA2;
        MessageDigest md = MessageDigest.getInstance(algorithm);
        A1 = username + ":" + realm + ":" + password;
        HashA1 = calculateMD5(A1);
        A2 = method + ":" + uri;
        HashA2 = calculateMD5(A2);

        String combo, finalHash;
        combo = HashA1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + HashA2;
        finalHash = calculateMD5(combo);
        return finalHash;
    }

    private static String calculateMD5(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(value.getBytes());
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 algorithm not available", e);
        }
    }

    private static String getUriPath(String uri) throws URISyntaxException {
        URI uriPath = new URI(uri);
        String path = uriPath.getPath();
        return path;
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
                .header("Authorization", AuthHeader)
                .build();

        return request;
    }

    public HttpResponse evaluateBasicMechanism(String uri) throws Exception {
        HttpRequest request = HttpRequest
                .newBuilder()
                .uri(new URI(uri))
                .header("Authorization", basicAuth(userName, password))
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

            String authHeader = response.headers().allValues("www-authenticate").get(0);

            if (authHeader.toLowerCase().startsWith("basic")) {
                response = evaluateBasicMechanism(uri);
                previousMechanism = "basic";
            } else if (authHeader.toLowerCase().startsWith("digest")) {
                updateAuthParams(authHeader);
                response = evaluateDigestMechanism(uri);
                previousMechanism = "digest";
            }
        }
        return response;
    }

}