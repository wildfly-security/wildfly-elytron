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
import org.wildfly.security.http.impl.AbstractBaseHttpTest;

import static org.wildfly.security.http.HttpConstants.BEARER_TOKEN;
import static org.wildfly.security.http.HttpConstants.UNAUTHORIZED;

import java.util.Collections;

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
}
