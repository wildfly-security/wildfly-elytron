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

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.wildfly.security.auth.client.ElytronXmlParser;
import org.wildfly.security.auth.client.InvalidAuthenticationConfigurationException;
import org.wildfly.security.http.client.utils.ClientCertSSLTestUtils;
import org.wildfly.security.auth.client.AuthenticationContext;

import java.io.IOException;
import java.net.URL;
import java.net.http.HttpResponse;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.cert.CertificateException;

import static java.security.AccessController.doPrivileged;

/**
 * Test for the ElytronHttpClient class
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
public class ElytronHttpClientCertTest {
    static final String RESOURCES = "./target/keystores/";
    private static SSLServerSocketTestInstance sslServerSocketTestInstancePort10001;
    private ElytronHttpClient elytronHttpClient = new ElytronHttpClient();

    @BeforeClass
    public static void before() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {
        ClientCertSSLTestUtils.createKeystores();

        sslServerSocketTestInstancePort10001 = new SSLServerSocketTestInstance(RESOURCES + "server1.keystore.jks", RESOURCES + "server1.truststore.jks", 10001);

        sslServerSocketTestInstancePort10001.run();
    }

    @AfterClass
    public static void after() {
        sslServerSocketTestInstancePort10001.stop();

        ClientCertSSLTestUtils.deleteKeystores();
    }

    @Test
    public void testElytronHttpClientCertAuth(){
        getAuthenticationContext("wildfly-config-http-client-cert.xml").run(() -> {
           try {
//               URI uri = new URI("https://localhost:10001");
               String uri = "https://localhost:10001";
               HttpResponse httpResponse = elytronHttpClient.connect(uri);
               Assert.assertEquals(200,httpResponse.statusCode());
           }catch (Exception e){
                e.printStackTrace();
           }
        });
    }

    private AuthenticationContext getAuthenticationContext(String path) {
        return doPrivileged((PrivilegedAction<AuthenticationContext>) () -> {
            URL config = getClass().getResource(path);
            try {
                return ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI()).create();
            } catch (Exception e) {
                e.printStackTrace();
                Assert.assertEquals("fine", e.getMessage());
                throw new InvalidAuthenticationConfigurationException(e);
            }
        });
    }
}
