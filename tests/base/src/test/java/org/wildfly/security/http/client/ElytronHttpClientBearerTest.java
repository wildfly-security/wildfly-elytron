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
package org.wildfly.security.http.client;

import org.junit.Test;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.auth.client.ElytronXmlParser;
import org.wildfly.security.auth.client.InvalidAuthenticationConfigurationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.basic.BasicMechanismFactory;
import org.wildfly.security.http.client.mechanism.basic.ElytronHttpClientBasicAuthMechanism;
import org.wildfly.security.http.impl.AbstractBaseHttpTest;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;

import java.net.URI;
import java.net.URL;
import java.net.http.HttpResponse;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Collections;
import java.util.function.Supplier;

import static java.security.AccessController.doPrivileged;

/**
 * Test for the ElytronHttpClient class
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
public class ElytronHttpClientBearerTest extends AbstractBaseHttpTest {
    private ElytronHttpClientBasicAuthMechanism elytronHttpClientBasicAuthMechanism = new ElytronHttpClientBasicAuthMechanism();
    public static Supplier<Provider[]> ELYTRON_PASSWORD_PROVIDERS = () -> new Provider[]{
            WildFlyElytronPasswordProvider.getInstance()
    };
    private ElytronHttpClient elytronHttpClient = new ElytronHttpClient();
    protected HttpServerAuthenticationMechanismFactory basicFactory = new BasicMechanismFactory(ELYTRON_PASSWORD_PROVIDERS.get());

    @Test
    public void testElytonHttpClientBasicAuthenticationMechanism() {
        AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT =
                doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);

        AuthenticationContext context = doPrivileged((PrivilegedAction<AuthenticationContext>) () -> {
            try {
                URL config = getClass().getResource("wildfly-config-http-client-bearer.xml");
                return ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI()).create();
            } catch (Throwable t) {
                throw new InvalidAuthenticationConfigurationException(t);
            }
        });
        context.run(() -> {
            try {
                HttpServerAuthenticationMechanism mechanism = basicFactory.createAuthenticationMechanism("BASIC", Collections.emptyMap(), getCallbackHandler("user1", "test-realm", "password1"));
                URI uri = new URI("http://localhost:8080/servlet-security/SecuredServlet");
                HttpResponse httpResponse = elytronHttpClient.connect(uri.toString());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
}