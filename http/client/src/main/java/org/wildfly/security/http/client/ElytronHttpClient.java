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

import org.apache.commons.codec.digest.DigestUtils;

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

    public HttpRequest getResponseHeader(String responseHeader) throws Exception{

        Map<String,String> authParams = getHeaderValue(responseHeader);

        String realm = authParams.get("realm");
        String domain = authParams.get("domain");
        String nonce = authParams.get("nonce");
        String opaque = authParams.get("opaque");
        String algorithm = authParams.get("algorithm");
        String qop = authParams.get("qop");

        String path = "/test";
        String uri = "http://localhost:8080"+path;

        String username = httpMechClientConfigUtil.getUsername(new URI(uri));
        String password = httpMechClientConfigUtil.getPassword(new URI(uri));

        String resp;
        if(qop==null){
            resp = computeDigestWithoutQop(path,nonce,username,password,"MD5",realm,"GET");
        }else{
            resp = computeDigestWithQop(path,nonce,"0a4f113b","00000001",username,password,"MD5",realm,qop,"GET");
        }

        HttpRequest request2 = HttpRequest
                .newBuilder()
                .uri(new URI(uri))
                .header("Authorization","Digest " +
                        "username=\"" + username + "\", " +
                        "realm=\"" + realm + "\"," +
                        "nonce=\"" + nonce + "\", " +
                        "uri=\"" + path + "\", " +
                        "qop=\"" + qop + "\", " +
                        "nc=00000001, " +
                        "cnonce=\"0a4f113b\", " +
                        "response=\"" + resp + "\", " +
                        "opaque=\"" + opaque + "\", " +
                        "algorithm="+algorithm)
                .build();
        return request2;

    }

    public Map<String,String> getHeaderValue(String responseHeader){
        Pattern pattern = Pattern.compile("(\\w+)=([^,\\s]+)");
        Matcher matcher = pattern.matcher(responseHeader);

        Map<String, String> authParams = new HashMap<String, String>();
        while (matcher.find()) {
            authParams.put(matcher.group(1), matcher.group(2));
        }

        for(String key : authParams.keySet()){
            String val = authParams.get(key);
            if(val.charAt(0)=='"' && val.charAt(val.length()-1)=='"'){
                val = val.substring(1,val.length()-1);
                authParams.replace(key,val);
            }
        }
        return authParams;
    }

    public HttpRequest getRequest2(String uri) throws Exception{
        String username = httpMechClientConfigUtil.getUsername(new URI(uri));
        String password = httpMechClientConfigUtil.getPassword(new URI(uri));
        HttpRequest request = HttpRequest.newBuilder().uri(new URI(uri)).build();
        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());
        String str = response.headers().allValues("www-authenticate").get(0);

        Map<String,String> authParams = getHeaderValue(str);

        String realm = authParams.get("realm");
        String domain = authParams.get("domain");
        String nonce = authParams.get("nonce");
        String opaque = authParams.get("opaque");
        String algorithm = authParams.get("algorithm");
        String qop = authParams.get("qop");

        System.out.println("nonce : " + nonce);

        String uriPath = getUriPath(uri);

        String resp;
        if(qop==null){
            resp = computeDigestWithoutQop(uriPath,nonce,username,password,"MD5",realm,"GET");
        }else{
            resp = computeDigestWithQop(uriPath,nonce,"0a4f113b","00000001",username,password,"MD5",realm,qop,"GET");
        }

        HttpRequest request2 = HttpRequest
                .newBuilder()
                .uri(new URI(uri))
                .header("Authorization","Digest " +
                        "username=\"" + username + "\", " +
                        "realm=\"" + realm + "\"," +
                        "nonce=\"" + nonce + "\", " +
                        "uri=\"" + uriPath + "\", " +
                        "qop=\"" + qop + "\", " +
                        "nc=00000001, " +
                        "cnonce=\"" + generateCNonce() +"\", " +
                        "response=\"" + resp + "\", " +
                        "opaque=\"" + opaque + "\", " +
                        "algorithm="+algorithm)
                .build();
        return request2;
    }

    private static String computeDigestWithoutQop(String uri, String nonce, String username, String password, String algorithm, String realm, String method) throws NoSuchAlgorithmException {
        String A1, HashA1, A2, HashA2;
        MessageDigest md = MessageDigest.getInstance(algorithm);
        A1 = username + ":" + realm + ":" + password;
        HashA1 = getMD5(A1);
        A2 = method + ":" + uri;
        HashA2 = getMD5(A2);
        String combo, finalHash;
        combo = HashA1 + ":" + nonce + ":" + HashA2;
        finalHash = DigestUtils.md5Hex(combo);
        return finalHash;
    }

    private static String computeDigestWithQop(String uri, String nonce, String cnonce, String nc, String username, String password, String algorithm, String realm, String qop, String method) throws NoSuchAlgorithmException{

        System.out.println("uri : "+ uri + " nonce " + nonce + " cnonce " + cnonce + " nc " + nc + " username " + username + " password " + password + " realm " + realm + " qop " + qop + " method " + method);
        String A1, HashA1, A2, HashA2;
        MessageDigest md = MessageDigest.getInstance(algorithm);
        A1 = username + ":" + realm + ":" + password;
        HashA1 = getMD5(A1);
        A2 = method + ":" + uri;
        HashA2 = getMD5(A2);

        String combo, finalHash;
        combo = HashA1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + HashA2;
        finalHash = getMD5(combo);
        return finalHash;
    }

    public static String getMD5(String value) {
        return DigestUtils.md5Hex(value).toString();
    }

    private static String getUriPath(String uri) throws URISyntaxException {
        URI uriPath = new URI(uri);
        String path = uriPath.getPath();
        return path;
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

    private String generateCNonce() {
        return Long.toString(System.nanoTime());
    }
}