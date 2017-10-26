/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.RSAKey;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.X500;

/**
 * Tests for generating self-signed X.509 certificates.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class SelfSignedX509CertificateAndSigningKeyTest {

    private static final X500Principal DN = new X500Principal("CN=bob smith, OU=jboss, O=red hat, L=raleigh, ST=north carolina, C=us");

    private static SelfSignedX509CertificateAndSigningKey.Builder populateBasicBuilder() throws Exception {
        SelfSignedX509CertificateAndSigningKey.Builder builder = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(DN);
        return builder;
    }

    // -- Successful self-signed X.509 certificate generation --

    @Test
    public void testBasicSelfSignedCertificate() throws Exception {
        SelfSignedX509CertificateAndSigningKey selfSignedX509CertificateAndSigningKey = populateBasicBuilder().build();
        X509Certificate certificate = selfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        PrivateKey signingKey = selfSignedX509CertificateAndSigningKey.getSigningKey();

        assertEquals(DN, certificate.getIssuerX500Principal());
        assertEquals(DN, certificate.getSubjectX500Principal());
        assertEquals("DSA", certificate.getPublicKey().getAlgorithm());
        assertEquals("DSA", signingKey.getAlgorithm());
        assertEquals("SHA256withDSA", certificate.getSigAlgName());
        assertEquals(2048, ((DSAKey) certificate.getPublicKey()).getParams().getP().bitLength());
        assertEquals(2048, ((DSAKey) signingKey).getParams().getP().bitLength());
        assertEquals(3, certificate.getVersion());
        assertNull(certificate.getCriticalExtensionOIDs());
        assertNull(certificate.getNonCriticalExtensionOIDs());
        try {
            certificate.checkValidity();
        } catch (Exception e) {
            fail("Exception not expected");
        }
    }

    @Test
    public void testSelfSignedCertificateWithKeyAndSignatureAlgorithm() throws Exception {
        SelfSignedX509CertificateAndSigningKey selfSignedX509CertificateAndSigningKey = populateBasicBuilder()
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA512withRSA")
                .build();
        X509Certificate certificate = selfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        PrivateKey signingKey = selfSignedX509CertificateAndSigningKey.getSigningKey();

        assertEquals("RSA", certificate.getPublicKey().getAlgorithm());
        assertEquals("RSA", signingKey.getAlgorithm());
        assertEquals("SHA512withRSA", certificate.getSigAlgName());
    }

    @Test
    public void testSelfSignedCertificateWithKeySize() throws Exception {
        int keySize = 1024;
        SelfSignedX509CertificateAndSigningKey selfSignedX509CertificateAndSigningKey = populateBasicBuilder()
                .setKeyAlgorithmName("RSA")
                .setKeySize(keySize)
                .build();
        X509Certificate certificate = selfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        PrivateKey signingKey = selfSignedX509CertificateAndSigningKey.getSigningKey();

        assertEquals(keySize, ((RSAKey) certificate.getPublicKey()).getModulus().bitLength());
        assertEquals(keySize, ((RSAKey) signingKey).getModulus().bitLength());
    }

    @Test
    public void testSelfSignedCertificateWithExtensions() throws Exception {
        final List<String> usage = Arrays.asList(X500.OID_KP_CLIENT_AUTH);
        SelfSignedX509CertificateAndSigningKey  selfSignedX509CertificateAndSigningKey = populateBasicBuilder()
                .addExtension(new ExtendedKeyUsageExtension(false, usage))
                .addExtension(new KeyUsageExtension(KeyUsage.digitalSignature))
                .addExtension(new SubjectAlternativeNamesExtension(
                        true,
                        Arrays.asList(new GeneralName.RFC822Name("bobsmith@example.com"), new GeneralName.DNSName("bobsmith.example.com"))))
                .build();
        X509Certificate certificate = selfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();

        assertEquals(2, certificate.getCriticalExtensionOIDs().size());
        assertEquals(1, certificate.getNonCriticalExtensionOIDs().size());

        assertEquals(usage, certificate.getExtendedKeyUsage());
        boolean[] keyUsage = certificate.getKeyUsage();
        assertNotNull(keyUsage);
        assertTrue(KeyUsage.digitalSignature.in(keyUsage));

        final Collection<List<?>> names = certificate.getSubjectAlternativeNames();
        assertEquals(2, names.size());
        final Iterator<List<?>> iterator = names.iterator();
        List<?> item = iterator.next();
        assertEquals(2, item.size());
        assertEquals(Integer.valueOf(GeneralName.RFC_822_NAME), item.get(0));
        assertEquals("bobsmith@example.com", item.get(1));
        item = iterator.next();
        assertEquals(2, item.size());
        assertEquals(Integer.valueOf(GeneralName.DNS_NAME), item.get(0));
        assertEquals("bobsmith.example.com", item.get(1));
    }

    @Test
    public void testSelfSignedCertificateWithNotValidBeforeAndAfterDates() throws Exception {
        final ZonedDateTime notValidBeforeDate = ZonedDateTime.of(2017, 10, 31, 23, 59, 59, 0, ZoneOffset.UTC);
        final ZonedDateTime notValidAfterDate = ZonedDateTime.of(2027, 10, 31, 23, 59, 59, 0, ZoneOffset.UTC);
        SelfSignedX509CertificateAndSigningKey  selfSignedX509CertificateAndSigningKey = populateBasicBuilder()
                .setNotValidBefore(notValidBeforeDate)
                .setNotValidAfter(notValidAfterDate)
                .build();
        X509Certificate certificate = selfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();

        assertEquals(Date.from(notValidBeforeDate.toInstant()), certificate.getNotBefore());
        assertEquals(Date.from(notValidAfterDate.toInstant()), certificate.getNotAfter());
    }

    @Test
    public void testPKCS10CertificateSigningRequestFromSelfSignedCertificate() throws Exception {
        SelfSignedX509CertificateAndSigningKey selfSignedX509CertificateAndSigningKey = populateBasicBuilder().build();
        PKCS10CertificateSigningRequest csr = selfSignedX509CertificateAndSigningKey.generatePKCS10CertificateSigningRequest();
        assertEquals(DN, csr.getSubjectDn());
        assertEquals(selfSignedX509CertificateAndSigningKey.getSelfSignedCertificate().getPublicKey(), csr.getPublicKey());
    }

    // -- Unsuccessful self-signed X.509 certificate generation --

    @Test
    public void testSelfSignedCertificateMissingDn() throws Exception {
        SelfSignedX509CertificateAndSigningKey.Builder builder = SelfSignedX509CertificateAndSigningKey.builder();

        try {
            builder.build();
            fail("Expected IllegalArgumentException not thrown");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testSelfSignedCertificateWithIncompatibleSignatureAlgorithm() throws Exception {
        SelfSignedX509CertificateAndSigningKey.Builder builder = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(DN)
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA1withDSA");

        try {
            builder.build();
            fail("Expected IllegalArgumentException not thrown");
        } catch (IllegalArgumentException expected) {
        }
    }

}
