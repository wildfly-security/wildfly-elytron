/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.sasl.gssapi;

import static org.junit.Assert.assertNotNull;

import java.io.File;

import org.ietf.jgss.GSSCredential;
import org.junit.Test;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.util.GSSCredentialSecurityFactory;
import org.wildfly.security.credential.GSSCredentialCredential;

/**
 * Testing of obtaining a {@link GSSCredential} from the {@link GSSSecurityFactory}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class GSSSecurityFactory {

    @Test
    public void testCreate() throws Exception {
        SecurityFactory<GSSCredentialCredential> factory = GSSCredentialSecurityFactory.builder()
                .setPrincipal("sasl/test_server_1@WILDFLY.ORG")
                .addMechanismOid(GSSCredentialSecurityFactory.KERBEROS_V5)
                .addMechanismOid(GSSCredentialSecurityFactory.SPNEGO)
                .setKeyTab(new File(GssapiTestSuite.serverKeyTab))
                .setIsServer(true)
                .setDebug(true)
                .build();

        GSSCredentialCredential credentialCredential = factory.create();
        assertNotNull("credentialCredential", credentialCredential);
        GSSCredential credential = credentialCredential.getGssCredential();
        assertNotNull("credential", credential);
    }

}
