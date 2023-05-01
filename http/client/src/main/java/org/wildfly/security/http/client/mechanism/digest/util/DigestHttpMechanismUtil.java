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

package org.wildfly.security.http.client.mechanism.digest.util;

import org.wildfly.security.digest.WildFlyElytronDigestProvider;
import org.wildfly.security.http.client.exception.ElytronHttpClientException;
import org.wildfly.security.http.client.utils.ElytronMessages;
import org.wildfly.security.mechanism.AuthenticationMechanismException;

import static org.wildfly.security.mechanism._private.ElytronMessages.log;

import static org.wildfly.security.mechanism.digest.DigestUtil.parseResponse;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.net.URI;
import java.net.http.HttpRequest;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Elytron client for HTTP authentication
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
public class DigestHttpMechanismUtil {

    private static final String AUTHORIZATION = "Authorization";
    private static final String CHALLENGE_PREFIX = "Digest ";

    public static HttpRequest createDigestRequest(URI uri, String userName, String password,String authHeader) throws AuthenticationMechanismException {
        Map<String,String> authParams = updateAuthParams(authHeader);
        String realm = authParams.getOrDefault("realm", null);
        String nonce = authParams.getOrDefault("nonce", null);
        String opaque = authParams.getOrDefault("opaque", null);
        String algorithm = authParams.getOrDefault("algorithm", "MD5");
        String qop = authParams.getOrDefault("qop", null);
        String uriPath = getUriPath(uri);
        String cnonce = generateCNonce();
        String nc = String.format("%08x", Integer.parseInt(authParams.getOrDefault("nc", String.valueOf(0))));

        String resp;
        if (qop == null) {
            resp = computeDigestWithoutQop(uriPath, nonce, userName, password, algorithm, realm, "GET");
        } else {
            resp = computeDigestWithQop(uriPath, nonce, cnonce, nc, userName, password, algorithm, realm, qop, "GET");
        }

        StringBuilder requestAuthHeader = new StringBuilder();
        requestAuthHeader.append("Digest ");
        requestAuthHeader.append("username=\"").append(userName).append("\", ");
        requestAuthHeader.append("realm=\"").append(realm).append("\", ");
        requestAuthHeader.append("nonce=\"").append(nonce).append("\", ");
        requestAuthHeader.append("uri=\"").append(uriPath).append("\", ");
        requestAuthHeader.append("qop=\"").append(qop).append("\", ");
        requestAuthHeader.append("nc=\"").append(nc).append("\", ");
        requestAuthHeader.append("cnonce=\"").append(cnonce).append("\", ");
        requestAuthHeader.append("response=\"").append(resp).append("\", ");
        requestAuthHeader.append("opaque=\"").append(opaque).append("\", ");
        requestAuthHeader.append("algorithm=").append(algorithm);

        HttpRequest request = HttpRequest
                .newBuilder()
                .uri(uri)
                .header(AUTHORIZATION, requestAuthHeader.toString())
                .build();
        int updateNonceCount = Integer.parseInt(authParams.getOrDefault("nc", "0")) + 1;
        authParams.put("nc", String.valueOf(updateNonceCount));
        return request;
    }

    private static Map<String,String> updateAuthParams(String authHeader) throws AuthenticationMechanismException {
        byte[] rawHeader = authHeader.substring(CHALLENGE_PREFIX.length()).getBytes(UTF_8);
        HashMap<String, byte[]> authval = parseResponse(rawHeader, UTF_8,false, log);
        Map<String,String> authParams = new HashMap<>();
        for(String headerKey : authval.keySet()){
            String headerValue = new String(authval.get(headerKey),UTF_8);
            authParams.put(headerKey,headerValue);
        }
        return authParams;
    }

    private static String computeDigestWithoutQop(String uri, String nonce, String username, String
            password, String algorithm, String realm, String method) {
        String A1, HashA1, A2, HashA2;
        A1 = username + ":" + realm + ":" + password;
        HashA1 = generateHash(A1,algorithm);
        A2 = method + ":" + uri;
        HashA2 = generateHash(A2,algorithm);
        String combo, finalHash;
        combo = HashA1 + ":" + nonce + ":" + HashA2;
        finalHash = generateHash(combo,algorithm);
        return finalHash;
    }

    private static String computeDigestWithQop(String uri, String nonce, String cnonce, String nc, String
            username, String password, String algorithm, String realm, String qop, String method) {

        System.out.println("uri : " + uri + " nonce " + nonce + " cnonce " + cnonce + " nc " + nc + " username " + username + " password " + password + " realm " + realm + " qop " + qop + " method " + method);
        String A1, HashA1, A2, HashA2;
        A1 = username + ":" + realm + ":" + password;
        HashA1 = generateHash(A1,algorithm);
        A2 = method + ":" + uri;
        HashA2 = generateHash(A2,algorithm);

        String combo, finalHash;
        combo = HashA1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + HashA2;
        finalHash = generateHash(combo,algorithm);
        return finalHash;
    }

    private static String generateHash(String value,String algorithm) {
        try {
            MessageDigest messageDigest;
            if(algorithm.equals("SHA-512-256")){
                messageDigest = MessageDigest.getInstance(algorithm, WildFlyElytronDigestProvider.getInstance());
            }
            else messageDigest = MessageDigest.getInstance(algorithm);
            messageDigest.update(value.getBytes());
            byte[] digest = messageDigest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new ElytronHttpClientException(ElytronMessages.log.digestAuthenticationAlgorithmNotAvailable());
        }
    }

    private static String getUriPath(URI uri) {
        return uri.getPath();
    }

    private static String generateCNonce() {
        return Long.toString(System.nanoTime());
    }
}
