/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.cert;

import mockit.Tested;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.impl.AbstractBaseHttpTest;

import javax.security.auth.x500.X500Principal;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import static org.wildfly.security.http.HttpConstants.*;

public class ClientCertAuthenticationMechanismTest extends AbstractBaseHttpTest {
    private static final Provider provider = WildFlyElytronHttpClientCertProvider.getInstance();

    @Tested
    private IdentityCache identityCache;

    @BeforeClass
    public static void registerCertProvider() {
        Security.insertProviderAt(provider, 1);
        SecurityDomain securityDomain = SecurityDomain.builder().addRealm("Simple", new SimpleMapBackedSecurityRealm()).build().setDefaultRealmName("Simple").build();
    }

    @AfterClass
    public static void removeCertProvider() {
        Security.removeProvider(provider.getName());
    }

    private HttpServerAuthenticationMechanism createMechanism() throws HttpAuthenticationException {
        Map<String, Object> props = new HashMap<>();
        return certFactory.createAuthenticationMechanism(CLIENT_CERT_NAME, props, getCallbackHandler("Duk3"));
    }

    //Test request with no certs
    @Test
    public void testNoCert() throws Exception {
        TestingHttpServerRequest request = new TestingHttpServerRequest(new String[]{});
        createMechanism().evaluateRequest(request);
        Assert.assertEquals(Status.NO_AUTH, request.getResult());
    }

    //Test request with invalid/unknown cert
    @Test
    public void testUnknownCert() throws Exception {
        TestingHttpServerRequest request = new TestingHttpServerRequest(new String[]{"Cert random"}, new X500Principal("CN=Duke, OU=Test, O=Wonderland, C=US"));
        createMechanism().evaluateRequest(request);
        Assert.assertEquals(Status.FAILED, request.getResult());
    }

    //Test request with known cert
    @Test
    public void testKnownCert() throws Exception {
        TestingHttpServerRequest request = new TestingHttpServerRequest(new String[]{"Cert test"}, new X500Principal("CN=Duk3, OU=T3st, O=W0nd3rl4nd, C=US"));
        createMechanism().evaluateRequest(request);
        Assert.assertEquals(Status.COMPLETE, request.getResult());
    }
}
