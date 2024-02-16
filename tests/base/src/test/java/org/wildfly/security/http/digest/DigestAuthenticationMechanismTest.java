/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.digest;

import mockit.integration.junit4.JMockit;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.impl.AbstractBaseHttpTest;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import static org.wildfly.security.http.HttpConstants.CONFIG_REALM;
import static org.wildfly.security.http.HttpConstants.DIGEST_NAME;
import static org.wildfly.security.http.HttpConstants.SHA256;
import static org.wildfly.security.http.HttpConstants.SHA512_256;
import static org.wildfly.security.http.HttpConstants.UNAUTHORIZED;

/**
 * Test of server side of the Digest HTTP mechanism.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class DigestAuthenticationMechanismTest extends AbstractBaseHttpTest {

    private static final Provider provider = WildFlyElytronHttpDigestProvider.getInstance();

    @BeforeClass
    public static void registerPasswordProvider() {
        Security.insertProviderAt(provider, 1);
    }

    @AfterClass
    public static void removePasswordProvider() {
        Security.removeProvider(provider.getName());
    }

    public void evaluateRequest(String[] authorization, HttpServerAuthenticationMechanism mechanism) throws Exception{
        TestingHttpServerRequest request = new TestingHttpServerRequest(authorization);
        mechanism.evaluateRequest(request);
        Assert.assertEquals(Status.COMPLETE, request.getResult());
    }

    public void evaluateRequest(String[] authorization, HttpServerAuthenticationMechanism mechanism, String uri) throws Exception{
        TestingHttpServerRequest request = new TestingHttpServerRequest(authorization, new URI(uri));
        mechanism.evaluateRequest(request);
        Assert.assertEquals(Status.COMPLETE, request.getResult());
    }

    @Test
    public void testRfc2617() throws Exception {
        mockDigestNonce("AAAAAQABsxiWa25/kpFxsPCrpDCFsjkTzs/Xr7RPsi/VVN6faYp21Hia3h4=");
        Map<String, Object> props = new HashMap<>();
        props.put(CONFIG_REALM, "testrealm@host.com");
        props.put("org.wildfly.security.http.validate-digest-uri", "false");
        HttpServerAuthenticationMechanism mechanism = digestFactory.createAuthenticationMechanism(DIGEST_NAME, props, getCallbackHandler("Mufasa", "testrealm@host.com", "Circle Of Life"));

        TestingHttpServerRequest request1 = new TestingHttpServerRequest(null);
        mechanism.evaluateRequest(request1);
        Assert.assertEquals(Status.NO_AUTH, request1.getResult());
        TestingHttpServerResponse response = request1.getResponse();
        Assert.assertEquals(UNAUTHORIZED, response.getStatusCode());
        Assert.assertEquals("Digest realm=\"testrealm@host.com\", nonce=\"AAAAAQABsxiWa25/kpFxsPCrpDCFsjkTzs/Xr7RPsi/VVN6faYp21Hia3h4=\", opaque=\"00000000000000000000000000000000\", algorithm=MD5, qop=auth", response.getAuthenticateHeader());

        evaluateRequest(new String[] {
                "Digest username=\"Mufasa\",\n" +
                        "                 realm=\"testrealm@host.com\",\n" +
                        "                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
                        "                 uri=\"/dir/index.html\",\n" +
                        "                 qop=auth,\n" +
                        "                 nc=00000001,\n" +
                        "                 cnonce=\"0a4f113b\",\n" +
                        "                 response=\"" + computeDigest("/dir/index.html", "dcd98b7102dd2f0e8b11d0f600bfb0c093", "0a4f113b", "00000001", "Mufasa", "Circle Of Life", "MD5", "testrealm@host.com", "auth", "GET") + "\",\n" +
                        "                 opaque=\"00000000000000000000000000000000\",\n" +
                        "                 algorithm=MD5"
        },mechanism);

        // test case insensitive
        evaluateRequest(new String[] {
                "DiGeSt username=\"Mufasa\",\n" +
                        "                 realm=\"testrealm@host.com\",\n" +
                        "                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
                        "                 uri=\"/dir/index.html\",\n" +
                        "                 qop=auth,\n" +
                        "                 nc=00000001,\n" +
                        "                 cnonce=\"0a4f113b\",\n" +
                        "                 response=\"" + computeDigest("/dir/index.html", "dcd98b7102dd2f0e8b11d0f600bfb0c093", "0a4f113b", "00000001", "Mufasa", "Circle Of Life", "MD5", "testrealm@host.com", "auth", "GET") + "\",\n" +
                        "                 opaque=\"00000000000000000000000000000000\",\n" +
                        "                 algorithm=MD5"
        },mechanism);
    }

    @Test
    public void testRfc2617EncodedQuery() throws Exception {
        mockDigestNonce("AAAAAQABsxiWa25/kpFxsPCrpDCFsjkTzs/Xr7RPsi/VVN6faYp21Hia3h4=");
        Map<String, Object> props = new HashMap<>();
        props.put(CONFIG_REALM, "testrealm@host.com");
        props.put("org.wildfly.security.http.validate-digest-uri", "true");
        HttpServerAuthenticationMechanism mechanism = digestFactory.createAuthenticationMechanism(DIGEST_NAME, props, getCallbackHandler("Mufasa", "testrealm@host.com", "Circle Of Life"));

        String path = "/dir/index.html?foo=b%2Fr";
        String uri = "http://localhost" + path;

        evaluateRequest(new String[]{
                "Digest username=\"Mufasa\",\n" +
                        "                 realm=\"testrealm@host.com\",\n" +
                        "                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
                        "                 uri=\"" + uri + "\",\n" +
                        "                 qop=auth,\n" +
                        "                 nc=00000001,\n" +
                        "                 cnonce=\"0a4f113b\",\n" +
                        "                 response=\"" + computeDigest("http://localhost/dir/index.html?foo=b%2Fr", "dcd98b7102dd2f0e8b11d0f600bfb0c093", "0a4f113b", "00000001", "Mufasa", "Circle Of Life", "MD5", "testrealm@host.com", "auth", "GET") + "\",\n" +
                        "                 opaque=\"00000000000000000000000000000000\",\n" +
                        "                 algorithm=MD5"
        },mechanism,uri);
    }

    @Test
    public void testRfc2617EncodedPath() throws Exception {
        mockDigestNonce("AAAAAQABsxiWa25/kpFxsPCrpDCFsjkTzs/Xr7RPsi/VVN6faYp21Hia3h4=");
        Map<String, Object> props = new HashMap<>();
        props.put(CONFIG_REALM, "testrealm@host.com");
        props.put("org.wildfly.security.http.validate-digest-uri", "true");
        HttpServerAuthenticationMechanism mechanism = digestFactory.createAuthenticationMechanism(DIGEST_NAME, props, getCallbackHandler("Mufasa", "testrealm@host.com", "Circle Of Life"));

        String path = "/dir/foo%2Fr/index.html?foo=b%2Fr";
        String uri = "http://localhost" + path;

        evaluateRequest(new String[] {
                "Digest username=\"Mufasa\",\n" +
                        "                 realm=\"testrealm@host.com\",\n" +
                        "                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
                        "                 uri=\"" + uri + "\",\n" +
                        "                 qop=auth,\n" +
                        "                 nc=00000001,\n" +
                        "                 cnonce=\"0a4f113b\",\n" +
                        "                 response=\"" + computeDigest("http://localhost/dir/foo%2Fr/index.html?foo=b%2Fr", "dcd98b7102dd2f0e8b11d0f600bfb0c093", "0a4f113b", "00000001", "Mufasa", "Circle Of Life", "MD5", "testrealm@host.com", "auth", "GET") + "\",\n" +
                        "                 opaque=\"00000000000000000000000000000000\",\n" +
                        "                 algorithm=MD5"
        },mechanism, uri);
    }

    @Test
    public void testRfc7616sha256() throws Exception {
        mockDigestNonce("7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v");
        Map<String, Object> props = new HashMap<>();
        props.put(CONFIG_REALM, "http-auth@example.org");
        props.put("org.wildfly.security.http.validate-digest-uri", "false");
        HttpServerAuthenticationMechanism mechanism = digestFactory.createAuthenticationMechanism(DIGEST_NAME + "-" + SHA256, props, getCallbackHandler("Mufasa", "http-auth@example.org", "Circle of Life"));

        TestingHttpServerRequest request1 = new TestingHttpServerRequest(null);
        mechanism.evaluateRequest(request1);
        Assert.assertEquals(Status.NO_AUTH, request1.getResult());
        TestingHttpServerResponse response = request1.getResponse();
        Assert.assertEquals(UNAUTHORIZED, response.getStatusCode());
        Assert.assertEquals("Digest realm=\"http-auth@example.org\", nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", opaque=\"00000000000000000000000000000000\", algorithm=SHA-256, qop=auth", response.getAuthenticateHeader());

        evaluateRequest(new String[] {
                "Digest username=\"Mufasa\",\n" +
                        "       realm=\"http-auth@example.org\",\n" +
                        "       uri=\"/dir/index.html\",\n" +
                        "       algorithm=SHA-256,\n" +
                        "       nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\n" +
                        "       nc=00000001,\n" +
                        "       cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\",\n" +
                        "       qop=auth,\n" +
                        "       response=\"" + computeDigest("/dir/index.html", "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", "00000001", "Mufasa", "Circle of Life", "SHA-256", "http-auth@example.org", "auth", "GET") + "\",\n" +
                        "       opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""
        },mechanism);
    }

    @Test
    public void testSha512_256() throws Exception {
        mockDigestNonce("5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK");
        Map<String, Object> props = new HashMap<>();
        props.put(CONFIG_REALM, "api@example.org");
        props.put("org.wildfly.security.http.validate-digest-uri", "false");
        HttpServerAuthenticationMechanism mechanism = digestFactory.createAuthenticationMechanism(DIGEST_NAME + "-" + SHA512_256, props, getCallbackHandler("J\u00E4s\u00F8n Doe", "api@example.org", "Secret, or not?"));

        TestingHttpServerRequest request1 = new TestingHttpServerRequest(null);
        mechanism.evaluateRequest(request1);
        Assert.assertEquals(Status.NO_AUTH, request1.getResult());
        TestingHttpServerResponse response = request1.getResponse();
        Assert.assertEquals(UNAUTHORIZED, response.getStatusCode());
        Assert.assertEquals("Digest realm=\"api@example.org\", nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", opaque=\"00000000000000000000000000000000\", algorithm=SHA-512-256, qop=auth", response.getAuthenticateHeader());

        evaluateRequest(new String[] {
                "Digest username*=UTF-8''J%C3%A4s%C3%B8n%20Doe,\n" +
                        "       realm=\"api@example.org\",\n" +
                        "       uri=\"/doe.json\",\n" +
                        "       algorithm=SHA-512-256,\n" +
                        "       nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\",\n" +
                        "       nc=00000001,\n" +
                        "       cnonce=\"NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v\",\n" +
                        "       qop=auth,\n" +
                        "       response=\"" + computeDigest("/doe.json", "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK", "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v", "00000001", "J\u00E4s\u00F8n Doe", "Secret, or not?", "SHA-512-256", "api@example.org", "auth", "GET") + "\",\n" +
                        "       opaque=\"00000000000000000000000000000000\",\n" +
                        "       userhash=false"
        },mechanism);
    }

    @Test
    public void testSha256WithDigestPassword() throws Exception {
        mockDigestNonce("5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK");
        Map<String, Object> props = new HashMap<>();
        props.put(CONFIG_REALM, "api@example.org");
        props.put("org.wildfly.security.http.validate-digest-uri", "false");
        HttpServerAuthenticationMechanism mechanism = digestFactory.createAuthenticationMechanism(DIGEST_NAME + "-" + SHA256, props, getCallbackHandler("J\u00E4s\u00F8n Doe", "api@example.org", "Secret, or not?", true));

        TestingHttpServerRequest request1 = new TestingHttpServerRequest(null);
        mechanism.evaluateRequest(request1);
        Assert.assertEquals(Status.NO_AUTH, request1.getResult());
        TestingHttpServerResponse response = request1.getResponse();
        Assert.assertEquals(UNAUTHORIZED, response.getStatusCode());
        Assert.assertEquals("Digest realm=\"api@example.org\", nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", opaque=\"00000000000000000000000000000000\", algorithm=SHA-256, qop=auth", response.getAuthenticateHeader());

        TestingHttpServerRequest request2 = new TestingHttpServerRequest(new String[] {
                "Digest username*=UTF-8''J%C3%A4s%C3%B8n%20Doe,\n" +
                        "       realm=\"api@example.org\",\n" +
                        "       uri=\"/doe.json\",\n" +
                        "       algorithm=SHA-256,\n" +
                        "       nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\",\n" +
                        "       nc=00000001,\n" +
                        "       cnonce=\"NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v\",\n" +
                        "       qop=auth,\n" +
                        "       response=\"" + computeDigest("/doe.json", "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK", "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v", "00000001", "J\u00E4s\u00F8n Doe", "Secret, or not?", "SHA-256", "api@example.org", "auth", "GET") + "\",\n" +
                        "       opaque=\"00000000000000000000000000000000\",\n" +
                        "       userhash=false"
        });
        mechanism.evaluateRequest(request2);
        Assert.assertEquals(Status.COMPLETE, request2.getResult());
    }

    @Test
    public void testDigestMD5Password() throws Exception {
        mockDigestNonce("5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK");
        Map<String, Object> props = new HashMap<>();
        props.put(CONFIG_REALM, "api@example.org");
        props.put("org.wildfly.security.http.validate-digest-uri", "false");
        HttpServerAuthenticationMechanism mechanism = digestFactory.createAuthenticationMechanism(DIGEST_NAME, props, getCallbackHandler("J\u00E4s\u00F8n Doe", "api@example.org", "Secret, or not?", true));

        TestingHttpServerRequest request1 = new TestingHttpServerRequest(null);
        mechanism.evaluateRequest(request1);
        Assert.assertEquals(Status.NO_AUTH, request1.getResult());
        TestingHttpServerResponse response = request1.getResponse();
        Assert.assertEquals(UNAUTHORIZED, response.getStatusCode());
        Assert.assertEquals("Digest realm=\"api@example.org\", nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", opaque=\"00000000000000000000000000000000\", algorithm=MD5, qop=auth", response.getAuthenticateHeader());

        TestingHttpServerRequest request2 = new TestingHttpServerRequest(new String[] {
                "Digest username*=UTF-8''J%C3%A4s%C3%B8n%20Doe,\n" +
                        "       realm=\"api@example.org\",\n" +
                        "       uri=\"/doe.json\",\n" +
                        "       algorithm=MD5,\n" +
                        "       nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\",\n" +
                        "       nc=00000001,\n" +
                        "       cnonce=\"NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v\",\n" +
                        "       qop=auth,\n" +
                        "       response=\"" + computeDigest("/doe.json", "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK", "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v", "00000001", "J\u00E4s\u00F8n Doe", "Secret, or not?", "MD5", "api@example.org", "auth", "GET") + "\",\n" +
                        "       opaque=\"00000000000000000000000000000000\",\n" +
                        "       userhash=false"
        });
        mechanism.evaluateRequest(request2);
        Assert.assertEquals(Status.COMPLETE, request2.getResult());
    }

    private String computeDigest(String uri, String nonce, String cnonce, String nc, String username, String password, String algorithm, String realm, String qop, String method) throws NoSuchAlgorithmException {
        String A1, HashA1, A2, HashA2;
        MessageDigest md = MessageDigest.getInstance(algorithm);
        A1 = username + ":" + realm + ":" + password;
        HashA1 = encode(A1, md);
        A2 = method + ":" + uri;
        HashA2 = encode(A2, md);
        String combo, finalHash;
        combo = HashA1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + HashA2;
        finalHash = encode(combo, md);
        return finalHash;
    }

    private String encode(String src, MessageDigest md) {
        char[] charArray = {
                '0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        };
        md.update(src.getBytes(StandardCharsets.UTF_8));
        byte[] digest = md.digest();
        StringBuilder res = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            int hashChar = ((b >>> 4) & 0xf);
            res.append(charArray[hashChar]);
            hashChar = (b & 0xf);
            res.append(charArray[hashChar]);
        }
        return res.toString();
    }
}