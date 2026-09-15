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

package org.wildfly.security.http.bearer;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.impl.AbstractBaseHttpTest;

import static org.wildfly.security.http.HttpConstants.BEARER_TOKEN;
import static org.wildfly.security.http.HttpConstants.CONFIG_BEARER_ENABLE_COOKIE_FALLBACK;
import static org.wildfly.security.http.HttpConstants.CONFIG_BEARER_TOKEN_COOKIE_NAME;
import static org.wildfly.security.http.HttpConstants.UNAUTHORIZED;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Test of server side of the Bearer HTTP mechanism.
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
public class BearerAuthenticationMechanismTest extends AbstractBaseHttpTest {

    @Test
    public void testBearerAuthenticationMechanism() throws Exception {
        HttpServerAuthenticationMechanism mechanism = bearerFactory.createAuthenticationMechanism(BEARER_TOKEN, Collections.emptyMap(), getCallbackHandler(null, "testrealm@host.com", null, "random"));

        //Test no authentication in progress
        TestingHttpServerRequest request1 = new TestingHttpServerRequest(new String[]{});
        mechanism.evaluateRequest(request1);
        Assert.assertEquals(Status.NO_AUTH, request1.getResult());

        //Test unsuccessful authentication
        TestingHttpServerRequest request2 = new TestingHttpServerRequest(new String[]{"Bearer test"});
        mechanism.evaluateRequest(request2);
        Assert.assertEquals(Status.FAILED, request2.getResult());
        Assert.assertEquals(UNAUTHORIZED, request2.getResponse().getStatusCode());

        //Test successful Authentication
        TestingHttpServerRequest request3 = new TestingHttpServerRequest(new String[]{"Bearer random"});
        mechanism.evaluateRequest(request3);
        Assert.assertEquals(Status.COMPLETE, request3.getResult());
    }

    /**
     * Cookie fallback enabled: no Authorization header, valid token present in the named cookie.
     * The mechanism must read the token from the cookie and authenticate successfully.
     */
    @Test
    public void testCookieFallback_noBearerHeader_validCookie_authenticates() throws Exception {
        Map<String, Object> props = new HashMap<>();
        props.put(CONFIG_BEARER_ENABLE_COOKIE_FALLBACK, "true");
        props.put(CONFIG_BEARER_TOKEN_COOKIE_NAME, "AUTH_TOKEN");
        HttpServerAuthenticationMechanism mechanism = bearerFactory.createAuthenticationMechanism(
                BEARER_TOKEN, props, getCallbackHandler(null, "testrealm@host.com", null, "secret"));

        List<HttpServerCookie> cookies = Collections.singletonList(
                HttpServerCookie.getInstance("AUTH_TOKEN", "secret", null, -1, "/", false, 0, true));
        TestingHttpServerRequest request = new TestingHttpServerRequest(
                null, URI.create("http://localhost/"), cookies);

        mechanism.evaluateRequest(request);

        Assert.assertEquals(Status.COMPLETE, request.getResult());
    }

    /**
     * Cookie fallback enabled: BOTH Authorization header AND a cookie are present.
     * The Authorization header must win, the cookie must be ignored.
     */
    @Test
    public void testCookieFallback_headerAndCookiePresent_headerWins() throws Exception {
        Map<String, Object> props = new HashMap<>();
        props.put(CONFIG_BEARER_ENABLE_COOKIE_FALLBACK, "true");
        props.put(CONFIG_BEARER_TOKEN_COOKIE_NAME, "AUTH_TOKEN");
        HttpServerAuthenticationMechanism mechanism = bearerFactory.createAuthenticationMechanism(
                BEARER_TOKEN, props, getCallbackHandler(null, "testrealm@host.com", null, "header_token"));

        // Cookie holds an invalid token; only the header is valid.
        List<HttpServerCookie> cookies = Collections.singletonList(
                HttpServerCookie.getInstance("AUTH_TOKEN", "wrong_token", null, -1, "/", false, 0, true));
        TestingHttpServerRequest request = new TestingHttpServerRequest(
                new String[]{"Bearer header_token"}, URI.create("http://localhost/"), cookies);

        mechanism.evaluateRequest(request);

        Assert.assertEquals(Status.COMPLETE, request.getResult());
    }

    /**
     * If Cookie fallback disabled: no Authorization header and valid token present in the cookie.
     * The mechanism must NOT consult the cookie and must report no authentication in progress.
     */
    @Test
    public void testCookieFallback_disabled_validCookie_noAuth() throws Exception {
        Map<String, Object> props = new HashMap<>();
        props.put(CONFIG_BEARER_ENABLE_COOKIE_FALLBACK, "false");
        props.put(CONFIG_BEARER_TOKEN_COOKIE_NAME, "AUTH_TOKEN");
        HttpServerAuthenticationMechanism mechanism = bearerFactory.createAuthenticationMechanism(
                BEARER_TOKEN, props, getCallbackHandler(null, "testrealm@host.com", null, "secret"));

        List<HttpServerCookie> cookies = Collections.singletonList(
                HttpServerCookie.getInstance("AUTH_TOKEN", "secret", null, -1, "/", false, 0, true));
        TestingHttpServerRequest request = new TestingHttpServerRequest(
                null, URI.create("http://localhost/"), cookies);

        mechanism.evaluateRequest(request);

        Assert.assertEquals(Status.NO_AUTH, request.getResult());
    }
}
