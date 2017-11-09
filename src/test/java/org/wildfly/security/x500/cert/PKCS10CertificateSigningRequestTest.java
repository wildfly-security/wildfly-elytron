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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.util.Alphabet;
import org.wildfly.security.util.CodePointIterator;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.X500;

/**
 * Tests for generating PKCS #10 certificate signing requests. The expected values for these tests
 * were generated using the {@code keytool} command.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class PKCS10CertificateSigningRequestTest {

    private static final String KEYSTORE = "/client.keystore";
    private static final String KEYSTORE_ALIAS = "testclient1";
    private static final char[] KEYSTORE_PASSWORD = "password".toCharArray();
    private static KeyStore keyStore;

    @BeforeClass
    public static void loadKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("jks");
        try (InputStream is = PKCS10CertificateSigningRequestTest.class.getResourceAsStream(KEYSTORE)) {
            ks.load(is, KEYSTORE_PASSWORD);
        }
        keyStore = ks;
    }

    private static PKCS10CertificateSigningRequest.Builder populateBasicBuilder() throws Exception {
        final Certificate certificate = keyStore.getCertificate(KEYSTORE_ALIAS);
        final PrivateKey signingKey = (PrivateKey) keyStore.getKey(KEYSTORE_ALIAS, KEYSTORE_PASSWORD);
        PKCS10CertificateSigningRequest.Builder builder = PKCS10CertificateSigningRequest.builder()
                .setCertificate(certificate)
                .setSigningKey(signingKey);
        return builder;
    }

    // -- Successful certificate signing requests --

    @Test
    public void testBasicCsr() throws Exception {
        String expectedCsr = "MIIC5zCCAc8CAQAwcjELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9s" +
                "aW5hMRAwDgYDVQQHEwdSYWxlaWdoMRAwDgYDVQQKEwdSZWQgSGF0MQ4wDAYDVQQL" +
                "EwVKQm9zczEWMBQGA1UEAxMNVGVzdCBDbGllbnQgMTCCASIwDQYJKoZIhvcNAQEB" +
                "BQADggEPADCCAQoCggEBAINleeVmU3ojW+thblXmLNcJKi8GSlHoD1jC9Ai1tv36" +
                "kaNCULxHU3evzvK8kamrgpGTZv++zSSWow/jWJBlo5lttlHiHtGB6AVlgnQcXD8m" +
                "E93Z6jhoPlDWvDRPLr0DKvU1YM4AVQcPG50gppBMav5TE4giEMC+Q2IGCu8oGzrV" +
                "JCVs8j/MMRz0GnExWXFv6aIMPXtbe47aTWVm2GEW9C0ZAJAuVaMJ1bujBmybISn4" +
                "sQWSp6IynXmMeJqHSzjRDE45YsadY43nZ5gHdNrorBuQo8oWCVQz0uXlEVIqXDKL" +
                "CjzNg9t97kUr2mpKXrNifKnFpbeu0m2hiUKjW/h7BbECAwEAAaAwMC4GCSqGSIb3" +
                "DQEJDjEhMB8wHQYDVR0OBBYEFLvOCZ2EA8nLRr/cy3/Y6I/QhhG6MA0GCSqGSIb3" +
                "DQEBCwUAA4IBAQCBPsS0wHCSUqwM7VHMKYjEoxzTypp8eh6K4igOW6ezYbpRNmSS" +
                "v6WWzboW4GdKBAK0Oh4O3NhLtTWLG+xhB2a9wIQrYRR/7rDEARWLf64yeBPaAqZ4" +
                "oB1snVVkr+fHHvUmdSJoI+xcFakCo08tKzUsQPIELnrAXAgBnhb3y63dIiPPViQG" +
                "3+AE5yQYBS9pGa9OyrcW1aAsqKkEsQNyZxjkG8gAGZRWpYaYbPO6QN+861fa7BPn" +
                "sYCDfiE/UYxHEvEVs4Y1jXnJ71bG7MFYh/WCdRRWLvaZaslUqpAEMWXxHuyBrZmd" +
                "HnxjeMuW0Z0kQQ9qcl27T5egSgP0vlGiY6cY";

        PKCS10CertificateSigningRequest csr = populateBasicBuilder().build();
        assertArrayEquals(getEncoded(expectedCsr), csr.getEncoded());
    }

    @Test
    public void testCsrWithSignatureAlgorithm() throws Exception {
        String expectedCsr = "MIIC5zCCAc8CAQAwcjELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9s" +
                "aW5hMRAwDgYDVQQHEwdSYWxlaWdoMRAwDgYDVQQKEwdSZWQgSGF0MQ4wDAYDVQQL" +
                "EwVKQm9zczEWMBQGA1UEAxMNVGVzdCBDbGllbnQgMTCCASIwDQYJKoZIhvcNAQEB" +
                "BQADggEPADCCAQoCggEBAINleeVmU3ojW+thblXmLNcJKi8GSlHoD1jC9Ai1tv36" +
                "kaNCULxHU3evzvK8kamrgpGTZv++zSSWow/jWJBlo5lttlHiHtGB6AVlgnQcXD8m" +
                "E93Z6jhoPlDWvDRPLr0DKvU1YM4AVQcPG50gppBMav5TE4giEMC+Q2IGCu8oGzrV" +
                "JCVs8j/MMRz0GnExWXFv6aIMPXtbe47aTWVm2GEW9C0ZAJAuVaMJ1bujBmybISn4" +
                "sQWSp6IynXmMeJqHSzjRDE45YsadY43nZ5gHdNrorBuQo8oWCVQz0uXlEVIqXDKL" +
                "CjzNg9t97kUr2mpKXrNifKnFpbeu0m2hiUKjW/h7BbECAwEAAaAwMC4GCSqGSIb3" +
                "DQEJDjEhMB8wHQYDVR0OBBYEFLvOCZ2EA8nLRr/cy3/Y6I/QhhG6MA0GCSqGSIb3" +
                "DQEBDQUAA4IBAQBFlWPvJZV2rkZISqJdlsPSq46FRSNIL0Ivg0MUPpn36cvnXM6f" +
                "O7F27opXonFAXSOZM3E6AhpUOAHJG5q0FYOS4tZQUxGI0+H06FyWiroP6hdsJjOQ" +
                "rCsUm7E7GQfN1p6hFYmnEcTrYXjx25PynSVaoabyB6yl7APkPmbXRp64WxUD8eXU" +
                "5KzbMxidymggfcQWHfyiTb8I7cg+Tn+SQ9ErTD+9qUsYUOsMtcWDAHGxwxlBEu8a" +
                "NogiC4EF/Js8qYUXKGD0RjL++WtWE2mMOKZT4aj0eQLzWlxtlMqDJ0V7sg+8j7iW" +
                "pqjLjCwaqUpsCHSt/2jMEI+zOXiCmIdjWsLd";

        PKCS10CertificateSigningRequest  csr = populateBasicBuilder().setSignatureAlgorithmName("SHA512withRSA").build();
        assertArrayEquals(getEncoded(expectedCsr), csr.getEncoded());
    }

    @Test
    public void testCsrWithSubjectDn() throws Exception {
        String expectedCsr = "MIIC5TCCAc0CAQAwcDELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9s" +
                "aW5hMRAwDgYDVQQHEwdSYWxlaWdoMRAwDgYDVQQKEwdSZWQgSGF0MQ4wDAYDVQQL" +
                "EwVKQm9zczEUMBIGA1UEAxMLQ2xpZW50IFRlc3QwggEiMA0GCSqGSIb3DQEBAQUA" +
                "A4IBDwAwggEKAoIBAQCDZXnlZlN6I1vrYW5V5izXCSovBkpR6A9YwvQItbb9+pGj" +
                "QlC8R1N3r87yvJGpq4KRk2b/vs0klqMP41iQZaOZbbZR4h7RgegFZYJ0HFw/JhPd" +
                "2eo4aD5Q1rw0Ty69Ayr1NWDOAFUHDxudIKaQTGr+UxOIIhDAvkNiBgrvKBs61SQl" +
                "bPI/zDEc9BpxMVlxb+miDD17W3uO2k1lZthhFvQtGQCQLlWjCdW7owZsmyEp+LEF" +
                "kqeiMp15jHiah0s40QxOOWLGnWON52eYB3Ta6KwbkKPKFglUM9Ll5RFSKlwyiwo8" +
                "zYPbfe5FK9pqSl6zYnypxaW3rtJtoYlCo1v4ewWxAgMBAAGgMDAuBgkqhkiG9w0B" +
                "CQ4xITAfMB0GA1UdDgQWBBS7zgmdhAPJy0a/3Mt/2OiP0IYRujANBgkqhkiG9w0B" +
                "AQsFAAOCAQEAGVXsKxtd6YOvWxr9o2a+qUn08JJOFLPzbyKRX7JHCyZQ7LSM1UUA" +
                "zRbh9WhKpkOHaTRIZi0aiTZmtJuN1spy9dDp3KzNxJ5Z/O2DUl2xX+FZj3zR1EHL" +
                "X8pK0seuewe7eq+zydToISBn355gbsw1Q9kqxSTTOHp6ndPexUxv/YaoXddJYCiY" +
                "d/ji9oQhrL3RkAClFus+8ylZpCuoOxqcPTil7oOm2RGDnxSNHI911dmXW8+Nbc89" +
                "oOeixfKfCZps35xn3fGJRpjd/WiLQbsL5a0jnIJ5A05nnRXMAaB9H9NJgHVlojtU" +
                "NQPrzT1J7ZLlGZGG10m5pJvGlBg8z7a1Gw==";

        PKCS10CertificateSigningRequest  csr = populateBasicBuilder()
                .setSubjectDn(new X500Principal("CN=Client Test, OU=JBoss, O=Red Hat, L=Raleigh, ST=North Carolina, C=US"))
                .build();
        assertArrayEquals(getEncoded(expectedCsr), csr.getEncoded());
    }

    @Test
    public void testCsrWithExtensions() throws Exception {
        String expectedCsr = "MIIDUDCCAjgCAQAwcjELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9s" +
                "aW5hMRAwDgYDVQQHEwdSYWxlaWdoMRAwDgYDVQQKEwdSZWQgSGF0MQ4wDAYDVQQL" +
                "EwVKQm9zczEWMBQGA1UEAxMNVGVzdCBDbGllbnQgMTCCASIwDQYJKoZIhvcNAQEB" +
                "BQADggEPADCCAQoCggEBAINleeVmU3ojW+thblXmLNcJKi8GSlHoD1jC9Ai1tv36" +
                "kaNCULxHU3evzvK8kamrgpGTZv++zSSWow/jWJBlo5lttlHiHtGB6AVlgnQcXD8m" +
                "E93Z6jhoPlDWvDRPLr0DKvU1YM4AVQcPG50gppBMav5TE4giEMC+Q2IGCu8oGzrV" +
                "JCVs8j/MMRz0GnExWXFv6aIMPXtbe47aTWVm2GEW9C0ZAJAuVaMJ1bujBmybISn4" +
                "sQWSp6IynXmMeJqHSzjRDE45YsadY43nZ5gHdNrorBuQo8oWCVQz0uXlEVIqXDKL" +
                "CjzNg9t97kUr2mpKXrNifKnFpbeu0m2hiUKjW/h7BbECAwEAAaCBmDCBlQYJKoZI" +
                "hvcNAQkOMYGHMIGEMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIH" +
                "gDA+BgNVHREBAf8ENDAygRd0ZXN0Y2xpZW50MUBleGFtcGxlLmNvbYIXdGVzdGNs" +
                "aWVudDEuZXhhbXBsZS5jb20wHQYDVR0OBBYEFLvOCZ2EA8nLRr/cy3/Y6I/QhhG6" +
                "MA0GCSqGSIb3DQEBCwUAA4IBAQAna5u2EBD0e89SpgKY1B4VliHAIIm+5fBdGm7Z" +
                "TRW6/o6jjTkXxCu2I7nmLNqPyAlx0kjZSdxlQedGrhN4ytZn2cS5Bgf4PSZd+p+F" +
                "SRFkONJRyUXE0NM9blAuo4UQEAfjmWl/8prlVrSBYE37PUhi6ClQK3zF+2ltP9OX" +
                "pPTqk5SrzK4IjS/1EfFPCYw93G7HippItjNnJXssk7GMfNh/4t3ABCUv/BD5q1JZ" +
                "T9N1GuJeORMksSR6sLzWg61A0L7QS+ogykVlXe5ZJXn1VWtImLbdTrLorM5Go+Ml" +
                "ffjqRM+MsymGUIsXmjASXPfWKkl/KpGJNRVh5b+RFrvK8ALj";

        PKCS10CertificateSigningRequest  csr = populateBasicBuilder()
                .addExtension(new ExtendedKeyUsageExtension(false, Arrays.asList(X500.OID_KP_CLIENT_AUTH)))
                .addExtension(new KeyUsageExtension(KeyUsage.digitalSignature))
                .addExtension(new SubjectAlternativeNamesExtension(
                        true,
                        Arrays.asList(new GeneralName.RFC822Name("testclient1@example.com"), new GeneralName.DNSName("testclient1.example.com"))))
                .build();
        assertArrayEquals(getEncoded(expectedCsr), csr.getEncoded());
    }

    @Test
    public void testCsrPem() throws Exception {
        String expectedCsr = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                "MIIC5zCCAc8CAQAwcjELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9s\n" +
                "aW5hMRAwDgYDVQQHEwdSYWxlaWdoMRAwDgYDVQQKEwdSZWQgSGF0MQ4wDAYDVQQL\n" +
                "EwVKQm9zczEWMBQGA1UEAxMNVGVzdCBDbGllbnQgMTCCASIwDQYJKoZIhvcNAQEB\n" +
                "BQADggEPADCCAQoCggEBAINleeVmU3ojW+thblXmLNcJKi8GSlHoD1jC9Ai1tv36\n" +
                "kaNCULxHU3evzvK8kamrgpGTZv++zSSWow/jWJBlo5lttlHiHtGB6AVlgnQcXD8m\n" +
                "E93Z6jhoPlDWvDRPLr0DKvU1YM4AVQcPG50gppBMav5TE4giEMC+Q2IGCu8oGzrV\n" +
                "JCVs8j/MMRz0GnExWXFv6aIMPXtbe47aTWVm2GEW9C0ZAJAuVaMJ1bujBmybISn4\n" +
                "sQWSp6IynXmMeJqHSzjRDE45YsadY43nZ5gHdNrorBuQo8oWCVQz0uXlEVIqXDKL\n" +
                "CjzNg9t97kUr2mpKXrNifKnFpbeu0m2hiUKjW/h7BbECAwEAAaAwMC4GCSqGSIb3\n" +
                "DQEJDjEhMB8wHQYDVR0OBBYEFLvOCZ2EA8nLRr/cy3/Y6I/QhhG6MA0GCSqGSIb3\n" +
                "DQEBCwUAA4IBAQCBPsS0wHCSUqwM7VHMKYjEoxzTypp8eh6K4igOW6ezYbpRNmSS\n" +
                "v6WWzboW4GdKBAK0Oh4O3NhLtTWLG+xhB2a9wIQrYRR/7rDEARWLf64yeBPaAqZ4\n" +
                "oB1snVVkr+fHHvUmdSJoI+xcFakCo08tKzUsQPIELnrAXAgBnhb3y63dIiPPViQG\n" +
                "3+AE5yQYBS9pGa9OyrcW1aAsqKkEsQNyZxjkG8gAGZRWpYaYbPO6QN+861fa7BPn\n" +
                "sYCDfiE/UYxHEvEVs4Y1jXnJ71bG7MFYh/WCdRRWLvaZaslUqpAEMWXxHuyBrZmd\n" +
                "HnxjeMuW0Z0kQQ9qcl27T5egSgP0vlGiY6cY\n" +
                "-----END CERTIFICATE REQUEST-----\n";

        PKCS10CertificateSigningRequest  csr = populateBasicBuilder().build();
        assertEquals(expectedCsr, new String(csr.getPem().toArray(), StandardCharsets.UTF_8));
    }

    // -- Unsuccessful certificate signing requests --

    @Test
    public void testCsrMissingCertificate() throws Exception {
        final PrivateKey signingKey = (PrivateKey) keyStore.getKey(KEYSTORE_ALIAS, KEYSTORE_PASSWORD);
        PKCS10CertificateSigningRequest.Builder builder = PKCS10CertificateSigningRequest.builder()
                .setSigningKey(signingKey);

        try {
            PKCS10CertificateSigningRequest csr = builder.build();
            fail("Expected IllegalArgumentException not thrown");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testCsrMissingSigningKey() throws Exception {
        final Certificate certificate = keyStore.getCertificate(KEYSTORE_ALIAS);
        PKCS10CertificateSigningRequest.Builder builder = PKCS10CertificateSigningRequest.builder()
                .setCertificate(certificate);

        try {
            PKCS10CertificateSigningRequest csr = builder.build();
            fail("Expected IllegalArgumentException not thrown");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testCsrIncompatibleSignatureAlgorithm() throws Exception {
        PKCS10CertificateSigningRequest.Builder builder  = populateBasicBuilder();
        builder.setSignatureAlgorithmName("SHA1withDSA");
        try {
            PKCS10CertificateSigningRequest csr = builder.build();
            fail("Expected IllegalArgumentException not thrown");
        } catch (IllegalArgumentException expected) {
        }
    }

    private static byte[] getEncoded(String csr) {
        return CodePointIterator.ofChars(csr.toCharArray()).base64Decode(Alphabet.Base64Alphabet.STANDARD, false).drain();
    }
}
