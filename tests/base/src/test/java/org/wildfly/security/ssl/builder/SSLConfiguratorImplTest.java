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

package org.wildfly.security.ssl.builder;

import org.junit.Test;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

import java.io.IOException;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class SSLConfiguratorImplTest {

    @Test
    public void testRejectNonExistentCipherSuite() throws GeneralSecurityException, IOException {
        SSLContext sslContext = new SSLContextBuilder().build().create();
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        SSLParameters params = socket.getSSLParameters();
        params.setCipherSuites(new String[]{"invalidCipherSuite", "TLS_RSA_WITH_AES_128_CBC_SHA"});
        socket.setSSLParameters(params);
        assertTrue(socket.getSSLParameters().getCipherSuites().length == 1 && socket.getSSLParameters().getCipherSuites()[0].equals("TLS_RSA_WITH_AES_128_CBC_SHA"));
    }

    @Test
    public void testRejectNonExistentProtocol() throws GeneralSecurityException, IOException {
        SSLContext sslContext = new SSLContextBuilder().build().create();
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        SSLParameters params = socket.getSSLParameters();
        List<String> protocols = Arrays.asList(params.getProtocols());
        assertTrue(protocols.contains("TLSv1.2") && protocols.contains("TLSv1.1"));
        params.setProtocols(new String[]{"invalidProtocol", "TLSv1.1"});
        socket.setSSLParameters(params);
        assertTrue(socket.getSSLParameters().getProtocols().length == 1 && socket.getSSLParameters().getProtocols()[0].equals("TLSv1.1"));
    }

    @Test
    public void testSetSSLParameters() {
        SSLParameters params = new SSLParameters();
        String[] cipherSuites = new String[]{"TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"};
        String[] protocols = new String[]{"TLSv1.2"};
        String[] passedCipherSuites = cipherSuites.clone();
        String[] passedProtocols = protocols.clone();
        List<SNIServerName> serverNames =  Collections.unmodifiableList(Arrays.asList(new SNIHostName("localhost")));
        List<SNIMatcher> sniMatchers = Collections.unmodifiableList(Arrays.asList(SNIHostName.createSNIMatcher("www\\.example\\.com")));
        final AlgorithmConstraints algorithmConstraints = new AlgorithmConstraints() {
            @Override
            public boolean permits(Set<CryptoPrimitive> set, String s, AlgorithmParameters algorithmParameters) {
                return false;
            }

            @Override
            public boolean permits(Set<CryptoPrimitive> set, Key key) {
                return false;
            }

            @Override
            public boolean permits(Set<CryptoPrimitive> set, String s, Key key, AlgorithmParameters algorithmParameters) {
                return false;
            }
        };
        params.setServerNames(serverNames);
        params.setCipherSuites(passedCipherSuites);
        params.setProtocols(passedProtocols);
        params.setSNIMatchers(sniMatchers);
        params.setAlgorithmConstraints(algorithmConstraints);
        params.setWantClientAuth(false);
        params.setNeedClientAuth(true);
        params.setUseCipherSuitesOrder(true);
        params.setEndpointIdentificationAlgorithm("HTTPS");

        SSLParameters copiedSSLParams = JDKSpecific.setSSLParameters(params);

        assertNotSame(copiedSSLParams, params);
        assertTrue(copiedSSLParams.getServerNames() != serverNames && copiedSSLParams.getServerNames().equals(serverNames));
        assertTrue(copiedSSLParams.getCipherSuites() != passedCipherSuites && Arrays.equals(copiedSSLParams.getCipherSuites(), cipherSuites));
        assertTrue(copiedSSLParams.getProtocols() != passedProtocols && Arrays.equals(copiedSSLParams.getProtocols(), protocols));
        assertTrue(copiedSSLParams.getSNIMatchers() != sniMatchers && copiedSSLParams.getSNIMatchers().equals(sniMatchers));
        assertSame(copiedSSLParams.getAlgorithmConstraints(), algorithmConstraints);
        assertFalse(copiedSSLParams.getWantClientAuth());
        assertTrue(copiedSSLParams.getNeedClientAuth());
        assertTrue(copiedSSLParams.getUseCipherSuitesOrder());
        assertEquals("HTTPS", copiedSSLParams.getEndpointIdentificationAlgorithm());
    }

}
