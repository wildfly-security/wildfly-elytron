/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class X509EvidenceVerificationSuiteChild {

    @Test
    public void testX509Auth() throws Exception {

        SecurityRealm securityRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextSupplier(LdapTestSuite.dirContextFactory.create())
                .identityMapping()
                    .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                    .setRdnIdentifier("uid")
                    .build()
                .x509EvidenceVerifier()
                    .addSerialNumberCertificateVerifier("x509serialNumber")
                    .addSubjectDnCertificateVerifier("x509subject")
                    .addDigestCertificateVerifier("x509digest", "SHA-1")
                    .addEncodedCertificateVerifier("usercertificate")
                    .build()
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(new NamePrincipal("scarab"));

        SupportLevel credentialSupport = realmIdentity.getEvidenceVerifySupport(X509PeerCertificateChainEvidence.class, null);
        assertEquals("Identity verification level support", SupportLevel.POSSIBLY_SUPPORTED, credentialSupport);

        X509Certificate scarab = loadCertificate("/ca/certs/04.pem"); // scarab
        X509Certificate ca = loadCertificate("/ca/cacert.pem"); // ca
        Evidence evidence = new X509PeerCertificateChainEvidence(scarab, ca);
        assertTrue(realmIdentity.verifyEvidence(evidence));
    }

    private X509Certificate loadCertificate(String name) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream is = X509EvidenceVerificationSuiteChild.class.getResourceAsStream(name);
        return (X509Certificate) certificateFactory.generateCertificate(is);
    }

}
