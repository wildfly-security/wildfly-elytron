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

package org.wildfly.security.http;

import mockit.integration.junit4.JMockit;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.http.impl.AbstractBaseHttpTest;

import javax.security.auth.callback.CallbackHandler;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.wildfly.security.http.HttpConstants.BASIC_NAME;
import static org.wildfly.security.http.HttpConstants.CONFIG_REALM;
import static org.wildfly.security.http.HttpConstants.DIGEST_NAME;
import static org.wildfly.security.http.HttpConstants.SHA256;
import static org.wildfly.security.http.HttpConstants.UNAUTHORIZED;

/**
 * Test of using multiple HTTP authentication mechanisms.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class HttpAuthenticatorTest extends AbstractBaseHttpTest {

    private TestingHttpExchangeSpi exchangeSpi = new TestingHttpExchangeSpi();
    private HttpAuthenticator authenticator;

    private void testOneOfThree() throws Exception {
        mockDigestNonce("7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v");

        Map<String, Object> digestProps = new HashMap<>();
        digestProps.put(CONFIG_REALM, "http-auth@example.org");

        CallbackHandler callbackHandler = getCallbackHandler("Mufasa", "http-auth@example.org", "Circle of Life");

        final List<HttpServerAuthenticationMechanism> mechanisms = new LinkedList<>();
        mechanisms.add(mechanismFactory.createAuthenticationMechanism(DIGEST_NAME, digestProps, callbackHandler));
        mechanisms.add(mechanismFactory.createAuthenticationMechanism(BASIC_NAME, Collections.emptyMap(), callbackHandler));
        mechanisms.add(mechanismFactory.createAuthenticationMechanism(DIGEST_NAME + "-" + SHA256, digestProps, callbackHandler));

        authenticator = HttpAuthenticator.builder()
                .setMechanismSupplier(() -> mechanisms)
                .setHttpExchangeSpi(exchangeSpi)
                .setRequired(true)
                .build();
        Assert.assertFalse(authenticator.authenticate());

        List<String> responses = exchangeSpi.getResponseAuthenticateHeaders();
        assertEquals("All three mechanisms provided authenticate response", 3, responses.size());
        Assert.assertEquals(UNAUTHORIZED, exchangeSpi.getStatusCode());
        Assert.assertEquals(null, exchangeSpi.getResult());
        exchangeSpi.setStatusCode(0);
    }

    @Test
    public void testDigestMd5() throws Exception {
        testOneOfThree();

        exchangeSpi.setRequestAuthorizationHeaders(Collections.singletonList(
                "Digest username=\"Mufasa\",\n" +
                        "       realm=\"http-auth@example.org\",\n" +
                        "       uri=\"/dir/index.html\",\n" +
                        "       algorithm=MD5,\n" +
                        "       nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\n" +
                        "       nc=00000001,\n" +
                        "       cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\",\n" +
                        "       qop=auth,\n" +
                        "       response=\"8ca523f5e9506fed4657c9700eebdbec\",\n" +
                        "       opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""
        ));
        Assert.assertTrue("Digest-MD5 successful", authenticator.authenticate());
        Assert.assertEquals(0, exchangeSpi.getStatusCode());
        Assert.assertEquals(Status.COMPLETE, exchangeSpi.getResult());
    }

    @Test
    public void testBasic() throws Exception {
        testOneOfThree();

        exchangeSpi.setRequestAuthorizationHeaders(Collections.singletonList(
                "Basic TXVmYXNhOkNpcmNsZSBvZiBMaWZl"
        ));
        Assert.assertTrue("Basic successful", authenticator.authenticate());
        Assert.assertEquals(0, exchangeSpi.getStatusCode());
        Assert.assertEquals(Status.COMPLETE, exchangeSpi.getResult());
    }

    @Test
    public void testDigestSha256() throws Exception {
        testOneOfThree();

        exchangeSpi.setRequestAuthorizationHeaders(Collections.singletonList(
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
        ));
        Assert.assertTrue("Digest-SHA-256 successful", authenticator.authenticate());
        Assert.assertEquals(0, exchangeSpi.getStatusCode());
        Assert.assertEquals(Status.COMPLETE, exchangeSpi.getResult());
    }

}
