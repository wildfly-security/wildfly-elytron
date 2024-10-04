/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2022 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.form;

import mockit.integration.junit4.JMockit;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.impl.AbstractBaseHttpTest;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Test of server side of the Form HTTP mechanism.
 *
 * @author <a href="mailto:pberan@redhat.com">Petr Beran</a>
 */
@RunWith(JMockit.class)
public class FormAuthenticationMechanismTest extends AbstractBaseHttpTest {

    /**
     * Tests proper redirect in case of invalid credentials if the error page is missing
     */
    @Test
    public void testFormWithoutErrorPage() throws Exception {
        Map<String, String> properties = new HashMap<>();
        properties.put(HttpConstants.CONFIG_REALM, "Realm");
        properties.put(HttpConstants.CONFIG_CONTEXT_PATH, "/application");
        properties.put(HttpConstants.CONFIG_LOGIN_PAGE, "/login.jsp");
        HttpServerAuthenticationMechanism mechanism = formFactory.createAuthenticationMechanism(HttpConstants.FORM_NAME,
                properties, getCallbackHandler("username", "Realm", "password"));

        TestingHttpServerRequest request = new TestingHttpServerRequest(HttpConstants.POST, new String[]{"", "password"},
                new URI("http://localhost:8080/application/j_security_check"));
        mechanism.evaluateRequest(request);
        TestingHttpServerResponse response = request.getResponse();

        Assert.assertEquals(response.getStatusCode(), HttpConstants.FOUND);
        Assert.assertEquals("http://localhost:8080/application", response.getLocation());
    }

    /**
     * Tests proper redirect in case of invalid credentials if the error page is configured
     */
    @Test
    public void testFormWithErrorPage() throws Exception {
        Map<String, String> properties = new HashMap<>();
        properties.put(HttpConstants.CONFIG_REALM, "Realm");
        properties.put(HttpConstants.CONFIG_CONTEXT_PATH, "/application");
        properties.put(HttpConstants.CONFIG_LOGIN_PAGE, "/login.jsp");
        properties.put(HttpConstants.CONFIG_ERROR_PAGE, "/error.jsp");
        HttpServerAuthenticationMechanism mechanism = formFactory.createAuthenticationMechanism(HttpConstants.FORM_NAME,
                properties, getCallbackHandler("username", "Realm", "password"));

        TestingHttpServerRequest request = new TestingHttpServerRequest(HttpConstants.POST, new String[]{"", "password"},
                new URI("http://localhost:8080/application/j_security_check"));
        mechanism.evaluateRequest(request);
        TestingHttpServerResponse response = request.getResponse();

        Assert.assertEquals(response.getStatusCode(), HttpConstants.FOUND);
        Assert.assertEquals("http://localhost:8080/application/error.jsp", response.getLocation());
    }
}
