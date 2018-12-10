/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.x500;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;
import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

/**
 * Tests for X500 utilities.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class X500Test {

    private static X509Certificate[] populateCertificateChain() throws Exception {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e);
        }
        final KeyPair[] keyPairs = new KeyPair[5];
        for (int i = 0; i < keyPairs.length; i++) {
            keyPairs[i] = keyPairGenerator.generateKeyPair();
        }
        final X509Certificate[] orderedCertificates = new X509Certificate[5];
        for (int i = 0; i < orderedCertificates.length; i++) {
            X509CertificateBuilder builder = new X509CertificateBuilder();
            X500PrincipalBuilder principalBuilder = new X500PrincipalBuilder();
            principalBuilder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME,
                    ASN1Encodable.ofUtf8String("bob" + i)));
            X500Principal dn = principalBuilder.build();
            builder.setSubjectDn(dn);
            if (i == orderedCertificates.length - 1) {
                // self-signed
                builder.setIssuerDn(dn);
                builder.setSigningKey(keyPairs[i].getPrivate());
            } else {
                principalBuilder = new X500PrincipalBuilder();
                principalBuilder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME,
                        ASN1Encodable.ofUtf8String("bob" + (i + 1))));
                X500Principal issuerDn = principalBuilder.build();
                builder.setIssuerDn(issuerDn);
                builder.setSigningKey(keyPairs[i + 1].getPrivate());
            }
            builder.setSignatureAlgorithmName("SHA256withRSA");
            builder.setPublicKey(keyPairs[i].getPublic());
            orderedCertificates[i] = builder.build();
        }
        return orderedCertificates;
    }

    @Test
    public void testAsOrderedX509CertificateChain() throws Exception {
        final X509Certificate[] orderedCertificates = populateCertificateChain();

        X509Certificate[] unorderedCertificates = new X509Certificate[1];
        unorderedCertificates[0] = orderedCertificates[4];
        assertArrayEquals(new X509Certificate[] { orderedCertificates[4] }, X500.asOrderedX509CertificateChain(orderedCertificates[4].getPublicKey(), unorderedCertificates));

        unorderedCertificates = new X509Certificate[5];
        unorderedCertificates[0] = orderedCertificates[3];
        unorderedCertificates[1] = orderedCertificates[0];
        unorderedCertificates[2] = orderedCertificates[4];
        unorderedCertificates[3] = orderedCertificates[1];
        unorderedCertificates[4] = orderedCertificates[2];
        assertArrayEquals(orderedCertificates, X500.asOrderedX509CertificateChain(orderedCertificates[0].getPublicKey(), unorderedCertificates));
    }

    @Test
    public void testAsOrderedX509CertificateChainInvalidValues() throws Exception {
        final X509Certificate[] orderedCertificates = populateCertificateChain();
        try {
            // without starting public key
            X500.asOrderedX509CertificateChain(orderedCertificates[0].getPublicKey(), new X509Certificate[] { orderedCertificates[3], orderedCertificates[1], orderedCertificates[2] });
            fail("Expected IllegalArgumentException not thrown");
        } catch (IllegalArgumentException expected) {
        }

        try {
            // incomplete array
            X500.asOrderedX509CertificateChain(orderedCertificates[0].getPublicKey(), new X509Certificate[] { orderedCertificates[4], orderedCertificates[0], orderedCertificates[3], orderedCertificates[1] });
            fail("Expected IllegalArgumentException not thrown");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testCreateX509CertificateChain() throws Exception {
        final X509Certificate[] orderedCertificates = populateCertificateChain();
        HashMap<Principal, HashSet<X509Certificate>> certificatesMap = new HashMap<>();

        certificatesMap = new HashMap<>();
        certificatesMap.put(orderedCertificates[4].getSubjectDN(), new HashSet<> (Arrays.asList(orderedCertificates[4])));
        assertArrayEquals(new X509Certificate[] { orderedCertificates[4] }, X500.createX509CertificateChain(orderedCertificates[4], certificatesMap));

        certificatesMap = new HashMap<>();
        for (int i = 0; i < orderedCertificates.length; i++) {
            certificatesMap.put(orderedCertificates[i].getSubjectDN(), new HashSet<> (Arrays.asList(orderedCertificates[i])));
        }
        assertArrayEquals(orderedCertificates, X500.createX509CertificateChain(orderedCertificates[0], certificatesMap));
    }

    @Test
    public void testCreateX509CertificateChainInvalidValues() throws Exception {
        final X509Certificate[] orderedCertificates = populateCertificateChain();
        HashMap<Principal, HashSet<X509Certificate>> certificatesMap = new HashMap<>();

        // incomplete map
        for (int i = 0; i < orderedCertificates.length; i+=2) {
            certificatesMap.put(orderedCertificates[i].getSubjectDN(), new HashSet<> (Arrays.asList(orderedCertificates[i])));
        }
        try {
            X500.createX509CertificateChain(orderedCertificates[0], certificatesMap);
            fail("Expected IllegalArgumentException not thrown");
        } catch (IllegalArgumentException expected) {
        }

        // invalid starting certificate
        for (int i = 2; i < orderedCertificates.length; i++) {
            certificatesMap.put(orderedCertificates[i].getSubjectDN(), new HashSet<> (Arrays.asList(orderedCertificates[i])));
        }
        try {
            X500.createX509CertificateChain(orderedCertificates[0], certificatesMap);
            fail("Expected IllegalArgumentException not thrown");
        } catch (IllegalArgumentException expected) {
        }
    }
}
