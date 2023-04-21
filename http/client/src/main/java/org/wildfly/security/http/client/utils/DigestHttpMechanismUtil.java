package org.wildfly.security.http.client.utils;

import org.wildfly.security.digest.WildFlyElytronDigestProvider;
import org.wildfly.security.http.client.exception.ElytronHttpClientException;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpRequest;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DigestHttpMechanismUtil {

    public HttpRequest createDigestRequest(String uri, String userName, String password, Map<String,String> authParams) throws Exception {
        String realm = authParams.getOrDefault("realm", null);
        String domain = authParams.getOrDefault("domain", null);
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

        HttpRequest request = HttpRequest
                .newBuilder()
                .uri(new URI(uri))
                .header("Authorization", "Digest " +
                        "username=\"" + userName + "\", " +
                        "realm=\"" + realm + "\"," +
                        "nonce=\"" + nonce + "\", " +
                        "uri=\"" + uriPath + "\", " +
                        "qop=\"" + qop + "\", " +
                        "nc=\"" + nc + "\"," +
                        "cnonce=\"" + cnonce + "\", " +
                        "response=\"" + resp + "\", " +
                        "opaque=\"" + opaque + "\", " +
                        "algorithm=" + algorithm)
                .build();
        int updateNonceCount = Integer.parseInt(authParams.getOrDefault("nc", "0")) + 1;
        authParams.put("nc", String.valueOf(updateNonceCount));
        return request;
    }

    public void updateAuthParams(String authHeader, Map<String,String> authParams) {
        Pattern realmPattern = Pattern.compile("realm=\"(.*?)\"");
        Pattern domainPattern = Pattern.compile("domain=\"(.*?)\"");
        Pattern noncePattern = Pattern.compile("nonce=\"(.*?)\"");
        Pattern opaquePattern = Pattern.compile("opaque=\"(.*?)\"");
        Pattern algorithmPattern = Pattern.compile("algorithm=(.+?)(?:,|$)");
        Pattern qopPattern = Pattern.compile("qop=\\s*\"?([^\"]*)\"?");

        Matcher realmMatcher = realmPattern.matcher(authHeader);
        if (realmMatcher.find()) {
            authParams.put("realm",realmMatcher.group(1));
        }
        Matcher domainMatcher = domainPattern.matcher(authHeader);
        if (domainMatcher.find()) {
            authParams.put("domain",domainMatcher.group(1));
        }
        Matcher nonceMatcher = noncePattern.matcher(authHeader);
        if (nonceMatcher.find()) {
            authParams.put("nonce",nonceMatcher.group(1));
        }
        Matcher opaqueMatcher = opaquePattern.matcher(authHeader);
        if (opaqueMatcher.find()) {
            authParams.put("opaque",opaqueMatcher.group(1));
        }
        Matcher algorithmMatcher = algorithmPattern.matcher(authHeader);
        if (algorithmMatcher.find()) {
            authParams.put("algorithm",algorithmMatcher.group(1));
        }
        Matcher qopMatcher = qopPattern.matcher(authHeader);
        if (qopMatcher.find()) {
            authParams.put("qop",qopMatcher.group(1));
        }
    }

    public String computeDigestWithoutQop(String uri, String nonce, String username, String
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

    public String computeDigestWithQop(String uri, String nonce, String cnonce, String nc, String
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

    public String generateHash(String value,String algorithm) {
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

    public String getUriPath(String uri) throws URISyntaxException {
        URI uriPath = new URI(uri);
        String path = uriPath.getPath();
        return path;
    }

    public String generateCNonce() {
        return Long.toString(System.nanoTime());
    }
}
