/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.external;

import static org.wildfly.security.http.HttpConstants.EXTERNAL_NAME;
import static org.wildfly.security.http.HttpConstants.FORBIDDEN;

import java.security.Provider;
import java.security.Security;
import java.util.Collections;

import mockit.integration.junit4.JMockit;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.impl.AbstractBaseHttpTest;

/**
 * Test of server side of the External HTTP mechanism.
 *
 * @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */
@RunWith(JMockit.class)
public class ExternalAuthenticationMechanismTest extends AbstractBaseHttpTest {

    private static final Provider provider = WildFlyElytronHttpExternalProvider.getInstance();

    @BeforeClass
    public static void registerProvider() {
        Security.insertProviderAt(provider, 1);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testExternalAuthenticationMechanism() throws Exception {
        HttpServerAuthenticationMechanism mechanism = externalFactory.createAuthenticationMechanism(EXTERNAL_NAME, Collections.emptyMap(), getCallbackHandler("remoteUser", "testrealm@host.com", null));

        //Test no authentication in progress (no remote user passed in externally)
        TestingHttpServerRequest request1 = new TestingHttpServerRequest(null);
        mechanism.evaluateRequest(request1);
        Assert.assertEquals(Status.NO_AUTH, request1.getResult());

        //Test unsuccessful authentication
        TestingHttpServerRequest request2 = new TestingHttpServerRequest(null);
        request2.setRemoteUser("wrongUser");
        mechanism.evaluateRequest(request2);
        Assert.assertEquals(Status.FAILED, request2.getResult());
        Assert.assertEquals(FORBIDDEN, request2.getResponse().getStatusCode());

        //Test successful authentication
        TestingHttpServerRequest request3 = new TestingHttpServerRequest(null);
        request3.setRemoteUser("remoteUser");
        mechanism.evaluateRequest(request3);
        Assert.assertEquals(Status.COMPLETE, request3.getResult());
    }
}
