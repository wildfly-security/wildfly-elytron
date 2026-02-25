/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.ssl;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.realm.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.ssl.test.util.CAGenerationTool;
import org.wildfly.security.ssl.test.util.CAGenerationTool.Identity;
import org.wildfly.security.ssl.test.util.DefinedCAIdentity;
import org.wildfly.security.ssl.test.util.DefinedIdentity;
import org.wildfly.security.x500.principal.X500AttributePrincipalDecoder;

/**
 * JDK 21 specific SSL tests that verify Elytron's SSL infrastructure
 * works correctly with JDK 21 features such as named groups and virtual threads.
 *
 * @author <a href="mailto:gatinmatei@yahoo.com">Matei-Alexandru Gatin</a>
 */
public class SSLContextJDK21Test {
    private static final String CA_PKCS_LOCATION = "./target/test-classes/pkcs12";

    private static CAGenerationTool caGenerationTool;
    private static SecurityDomain securityDomain;

    @BeforeClass
    public static void setUp() throws Exception {

        caGenerationTool = CAGenerationTool.builder()
                .setBaseDir(CA_PKCS_LOCATION)
                .setRequestIdentities(Identity.LADYBIRD, Identity.SCARAB)
                .build();

        SecurityRealm securityRealm = new KeyStoreBackedSecurityRealm(caGenerationTool.getBeetlesKeyStore());
        securityDomain = SecurityDomain.builder()
                .addRealm("KeystoreRealm", securityRealm)
                .build()
                .setDefaultRealmName("KeystoreRealm")
                .setPrincipalDecoder(new X500AttributePrincipalDecoder("2.5.4.3", 1))
                .setPreRealmRewriter((String s) -> s.toLowerCase(Locale.ENGLISH))
                .setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.ALL)
                .build();
    }

    @AfterClass
    public static void cleanUp() throws IOException {
        caGenerationTool.close();
    }

    @Test
    public void testNamedGroupsOnElytronSSLContext() throws Exception {
        final String CIPHER_SUITE = "TLS_AES_128_GCM_SHA256";

        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedIdentity scarab = caGenerationTool.getDefinedIdentity(Identity.SCARAB);

        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setCipherSuiteSelector(CipherSuiteSelector.fromNamesString(CIPHER_SUITE))
                .setKeyManager(scarab.createKeyManager())
                .setTrustManager(ca.createTrustManager())
                .setNeedClientAuth(true)
                .build().create();

        SSLParameters params = serverContext.getDefaultSSLParameters();
        String[] namedGroups = params.getNamedGroups();

        assertNotNull("Named groups should be available on JDK21+", namedGroups);
        assertTrue("At least one named group should be present", namedGroups.length > 0);
    }

    @Test
    public void testElytronSSLContextOnVirtualThread() throws Exception {
        final String CIPHER_SUITE = "TLS_AES_128_GCM_SHA256";

        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedIdentity scarab = caGenerationTool.getDefinedIdentity(Identity.SCARAB);

        AtomicReference<Throwable> failure = new AtomicReference<>();

        Thread vThread = Thread.ofVirtual().start(() -> {
            try {

                SSLContext serverContext = new SSLContextBuilder()
                        .setSecurityDomain(securityDomain)
                        .setCipherSuiteSelector(CipherSuiteSelector.fromNamesString(CIPHER_SUITE))
                        .setKeyManager(scarab.createKeyManager())
                        .setTrustManager(ca.createTrustManager())
                        .setNeedClientAuth(true)
                        .build().create();

                assertNotNull("SSLContext should be accessible from virtual thread", serverContext);

                SSLParameters params = serverContext.getDefaultSSLParameters();
                assertNotNull("SSLParameters should be accessible from virtual thread", params);
            } catch (Throwable e) {
                failure.set(e);
            }
        });

        vThread.join(5000);

        if (failure.get() != null) {
            fail("Virtual thread failed: " + failure.get().getMessage());
        }
    }
}
