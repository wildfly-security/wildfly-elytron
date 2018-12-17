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

package org.wildfly.security.util;

import org.junit.Test;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

import javax.security.auth.x500.X500Principal;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
//has dependency on wildfly-elytron-x500-cert because of X509Certificate, X509CertificateBuilder and SelfSignedX509CertificateAndSigningKey
public class PemTest {

    private SelfSignedX509CertificateAndSigningKey createIssuerCertificate() {
        X500Principal DN = new X500Principal("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA");

        SelfSignedX509CertificateAndSigningKey certificate = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(DN)
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA1withRSA")
                .addExtension(false, "BasicConstraints", "CA:true,pathlen:2147483647")
                .build();

        return certificate;
    }

    private X509Certificate createSubjectCertificate(SelfSignedX509CertificateAndSigningKey issuerCertificate) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair generatedKeys = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = generatedKeys.getPublic();

        X500Principal issuerDN = new X500Principal("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA");
        X500Principal subjectDN = new X500Principal("O=Elytron, OU=Elytron, C=UK, ST=Elytron, CN=Firefly");

        X509Certificate subjectCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(subjectDN)
                .setSignatureAlgorithmName("SHA1withRSA")
                .setSigningKey(issuerCertificate.getSigningKey())
                .setPublicKey(publicKey)
                .build();

        return subjectCertificate;
    }

    private byte[] createPemAsBytes(X509Certificate certificate) {
        ByteStringBuilder target = new ByteStringBuilder();
        Pem.generatePemX509Certificate(target, certificate);
        return target.toArray();
    }

    @Test
    public void testEncodeDecodeRSAPublicKey() throws Exception {
        assertParsing(KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic());
    }

    @Test
    public void testEncodeDecodeDSAPublicKey() throws Exception {
        assertParsing(KeyPairGenerator.getInstance("DSA").generateKeyPair().getPublic());
    }

    @Test
    public void testEncodeDecodeECPublicKey() throws Exception {
        assertParsing(KeyPairGenerator.getInstance("EC").generateKeyPair().getPublic());
    }

    /**
     * Motivated by ELY-1300
     */
    @Test
    public void testParsePemX509Certificate01() throws Exception {
        SelfSignedX509CertificateAndSigningKey issuerCertificate = createIssuerCertificate();

        X509Certificate subjectCertificate = createSubjectCertificate(issuerCertificate);

        byte[] pemBytes = createPemAsBytes(subjectCertificate);

        assertNotNull(Pem.parsePemX509Certificate(CodePointIterator.ofUtf8Bytes(pemBytes)));
    }

    /**
     * Motivated by ELY-1301
     */
    @Test
    public void testParsePemX509CertificateCacert() throws Exception {
        SelfSignedX509CertificateAndSigningKey certificate = createIssuerCertificate();

        byte[] pemBytes = createPemAsBytes(certificate.getSelfSignedCertificate());

        assertNotNull(Pem.parsePemX509Certificate(CodePointIterator.ofUtf8Bytes(pemBytes)));
    }

    private void assertParsing(PublicKey publicKey) {
        ByteStringBuilder publicKeyPem = new ByteStringBuilder();

        Pem.generatePemPublicKey(publicKeyPem, publicKey);

        PublicKey parsedKey = Pem.parsePemPublicKey(CodePointIterator.ofUtf8Bytes(publicKeyPem.toArray()));

        assertNotNull(parsedKey);
        assertArrayEquals(publicKey.getEncoded(), parsedKey.getEncoded());
    }

    @Test
    public void testGeneratePemX509Certificate() throws Exception {
        String expectedPemCertificate = "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIDjTCCAnWgAwIBAgIJANOjc2u+sqarMA0GCSqGSIb3DQEBBQUAMH0xEzARBgNV" + System.lineSeparator() +
                "BAMMCkVseXRyb24gQ0ExEDAOBgNVBAgMB0VseXRyb24xCzAJBgNVBAYTAlVLMSIw" + System.lineSeparator() +
                "IAYJKoZIhvcNAQkBFhNlbHl0cm9uQHdpbGRmbHkub3JnMSMwIQYDVQQKDBpSb290" + System.lineSeparator() +
                "IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xNjAxMjgxOTA3MTRaFw0yNjAxMjUx" + System.lineSeparator() +
                "OTA3MTRaMH0xEzARBgNVBAMMCkVseXRyb24gQ0ExEDAOBgNVBAgMB0VseXRyb24x" + System.lineSeparator() +
                "CzAJBgNVBAYTAlVLMSIwIAYJKoZIhvcNAQkBFhNlbHl0cm9uQHdpbGRmbHkub3Jn" + System.lineSeparator() +
                "MSMwIQYDVQQKDBpSb290IENlcnRpZmljYXRlIEF1dGhvcml0eTCCASIwDQYJKoZI" + System.lineSeparator() +
                "hvcNAQEBBQADggEPADCCAQoCggEBANid0js/NWlA8HUtysx/AWHy/u8bnifacoGO" + System.lineSeparator() +
                "FjozbfElfSa601CATKp1eGqV0B6s179XuIj6UMwJqK6oM05eFZm353Tt7+G5C2/u" + System.lineSeparator() +
                "gaU7HW9hMVf91Si3OK6CunK9EWj19OrUBx7eO376cwPUulCs51puTKAjezMCKbTS" + System.lineSeparator() +
                "RJPdPwZiB/I+LqZdopa2eQgQzsJqIGf93YWjpX3UHnqObuvaieUdTIyM89LR1Vej" + System.lineSeparator() +
                "rASdz5aWD62A5si/gl4t+1pRywDiFkQ8PWhLkm7QIoainchF2UtsSOZgG5aKqtd9" + System.lineSeparator() +
                "c63N+3uwxMP5qSf0UoYJiQ925mjlNKoUOWj27fQAqMvV9EX2NLkCAwEAAaMQMA4w" + System.lineSeparator() +
                "DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEA0mZZlY10nniGr3OLYZ5V" + System.lineSeparator() +
                "8QvlEShllrwg3KlKPU5Lk/U0zG1stYWGeorkmYIuyVevxrHCIYpEAf3fmbZRbZlC" + System.lineSeparator() +
                "lEE4gVK6QCISqbkdPQrgdPSEq7hyLt/Ays0RsRApiddMQ/humMxFZgIfYXPiA4c4" + System.lineSeparator() +
                "6pjjMKLbikcd1lKAmcJSynixFoThqn8gAOkHbZZ9+/S0Bi+HLt1gVnbAsmrKqtdi" + System.lineSeparator() +
                "14d/WJdpLxpUmgAA39oVl5oasG8ImIXnXIU7tyE9pNBDtfOcxwpF/Cnh6kqcGoHL" + System.lineSeparator() +
                "ArwwQuSo6w9fpOQ1AsbjTz4xnWHTPewWCfcfKS6qmEn93c0Dfs/FVc1f2QEXdsLH" + System.lineSeparator() +
                "Mg==" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator();

        X509Certificate certificate = Pem.parsePemX509Certificate(CodePointIterator.ofString(expectedPemCertificate));
        ByteStringBuilder target = new ByteStringBuilder();
        Pem.generatePemX509Certificate(target, certificate);

        assertEquals(expectedPemCertificate, new String(target.toArray(), StandardCharsets.UTF_8));
    }
}
