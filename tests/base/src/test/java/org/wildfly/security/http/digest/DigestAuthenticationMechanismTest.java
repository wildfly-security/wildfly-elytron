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

        TestingHttpServerRequest request2 = new TestingHttpServerRequest(new String[] {
                "Digest username=\"Mufasa\",\n" +
                "                 realm=\"testrealm@host.com\",\n" +
                "                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\n" +
                "                 uri=\"/dir/index.html\",\n" +
                "                 qop=auth,\n" +
                "                 nc=00000001,\n" +
                "                 cnonce=\"0a4f113b\",\n" +
                "                 response=\"6629fae49393a05397450978507c4ef1\",\n" +
                "                 opaque=\"00000000000000000000000000000000\",\n" +
                "                 algorithm=MD5"
        });
        mechanism.evaluateRequest(request2);
        Assert.assertEquals(Status.COMPLETE, request2.getResult());
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

        TestingHttpServerRequest request2 = new TestingHttpServerRequest(new String[] {
                "Digest username=\"Mufasa\",\n" +
                "       realm=\"http-auth@example.org\",\n" +
                "       uri=\"/dir/index.html\",\n" +
                "       algorithm=SHA-256,\n" +
                "       nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\n" +
                "       nc=00000001,\n" +
                "       cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\",\n" +
                "       qop=auth,\n" +
                "       response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\",\n" +
                "       opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""
        });
        mechanism.evaluateRequest(request2);
        Assert.assertEquals(Status.COMPLETE, request2.getResult());
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

        TestingHttpServerRequest request2 = new TestingHttpServerRequest(new String[] {
                "Digest username*=UTF-8''J%C3%A4s%C3%B8n%20Doe,\n" +
                "       realm=\"api@example.org\",\n" +
                "       uri=\"/doe.json\",\n" +
                "       algorithm=SHA-512-256,\n" +
                "       nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\",\n" +
                "       nc=00000001,\n" +
                "       cnonce=\"NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v\",\n" +
                "       qop=auth,\n" +
                "       response=\"3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5\",\n" +
                "       opaque=\"00000000000000000000000000000000\",\n" +
                "       userhash=false"
        });
        mechanism.evaluateRequest(request2);
        Assert.assertEquals(Status.COMPLETE, request2.getResult());
    }
}
