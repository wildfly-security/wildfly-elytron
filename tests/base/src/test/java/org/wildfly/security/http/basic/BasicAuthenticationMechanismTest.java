/*
 * Copyright 2022 JBoss by Red Hat.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.http.basic;

import java.util.Collections;
import java.util.List;
import mockit.integration.junit4.JMockit;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.impl.AbstractBaseHttpTest;
import org.wildfly.security.http.sfbasic.BasicMechanismFactory;

/**
 * Test for the Basic and stateful Basic HTTP mechanisms. Using the examples
 * from the <a href="https://datatracker.ietf.org/doc/html/rfc7617">rfc7617</a>.
 *
 * @author rmartinc
 */
@RunWith(JMockit.class)
public class BasicAuthenticationMechanismTest extends AbstractBaseHttpTest {

    public void testBasic(String username, String realm, String password, String authorization, boolean wrongPassword) throws Exception {
        HttpServerAuthenticationMechanism mechanism = basicFactory.createAuthenticationMechanism(HttpConstants.BASIC_NAME,
                Collections.singletonMap(HttpConstants.CONFIG_REALM, realm), getCallbackHandler(username, realm, password));

        // request without authorization, it should be 401 and response added
        TestingHttpServerRequest request = new TestingHttpServerRequest(null);
        mechanism.evaluateRequest(request);
        Assert.assertEquals(Status.NO_AUTH, request.getResult());
        TestingHttpServerResponse response = request.getResponse();
        Assert.assertEquals(HttpConstants.UNAUTHORIZED, response.getStatusCode());
        Assert.assertEquals("Basic realm=\"" + realm + "\"", response.getAuthenticateHeader());

        // send the authorization header and check everything OK
        request = new TestingHttpServerRequest(new String[] {authorization});
        mechanism.evaluateRequest(request);

        if(wrongPassword){// request with incorrect password
            response = request.getResponse();
            Assert.assertEquals(HttpConstants.UNAUTHORIZED, response.getStatusCode());
        } else {
            Assert.assertEquals(AbstractBaseHttpTest.Status.COMPLETE, request.getResult());
        }
    }

    private void testBasic(String username, String realm, String password, String authorization) throws Exception {
        testBasic(username, realm, password, authorization, false);
    }

    @Test
    public void testBasicRFC7617Examples() throws Exception {
        testBasic("Aladdin", "WallyWorld", "open sesame", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        testBasic("test", "foo", "123\u00A3", "Basic dGVzdDoxMjPCow==");
        // test case insensitive
        testBasic("Aladdin", "WallyWorld", "open sesame", "basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        testBasic("test", "foo", "123\u00A3", "BASIC dGVzdDoxMjPCow==");
        // test incorrect password
        testBasic("Aladdin", "WallyWorld", "open sesame", "basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        testBasic("Aladdin", "WallyWorld", "sesame", "basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",true);
    }

    public void testStatefulBasic(String username, String realm, String password, String authorization) throws Exception {
        HttpServerAuthenticationMechanism mechanism = statefulBasicFactory.createAuthenticationMechanism(BasicMechanismFactory.STATEFUL_BASIC_NAME,
                Collections.singletonMap(HttpConstants.CONFIG_REALM, realm), getCallbackHandler(username, realm, password));

        // request without authorization, it should be 401 and response added
        TestingHttpServerRequest request = new TestingHttpServerRequest(null);
        mechanism.evaluateRequest(request);
        Assert.assertEquals(Status.NO_AUTH, request.getResult());
        TestingHttpServerResponse response = request.getResponse();
        Assert.assertEquals(HttpConstants.UNAUTHORIZED, response.getStatusCode());
        Assert.assertEquals("Basic realm=\"" + realm + "\"", response.getAuthenticateHeader());

        // send the authorization header and check everything OK
        request = new TestingHttpServerRequest(new String[] {authorization});
        mechanism.evaluateRequest(request);
        Assert.assertEquals(AbstractBaseHttpTest.Status.COMPLETE, request.getResult());
        response = request.getResponse();
        List<HttpServerCookie> cookies =  response.getCookies();
        Assert.assertNotNull(cookies);
        Assert.assertEquals(1, cookies.size());
        Assert.assertEquals(BasicMechanismFactory.COOKIE_NAME, cookies.get(0).getName());

        // send just the cookie and it should work again
        request = new TestingHttpServerRequest(null, null, cookies);
        mechanism.evaluateRequest(request);
        Assert.assertEquals(AbstractBaseHttpTest.Status.COMPLETE, request.getResult());
    }

    @Test
    public void testStatefulBasicRFC7617Examples() throws Exception {
        testStatefulBasic("Aladdin", "WallyWorld", "open sesame", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        testStatefulBasic("test", "foo", "123\u00A3", "Basic dGVzdDoxMjPCow==");
        // test case insensitive
        testStatefulBasic("Aladdin", "WallyWorld", "open sesame", "basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        testStatefulBasic("test", "foo", "123\u00A3", "BASIC dGVzdDoxMjPCow==");
    }
}
