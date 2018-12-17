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

package org.wildfly.security.x500.cert;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;
import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.X500;
import org.wildfly.security.x500.X500AttributeTypeAndValue;
import org.wildfly.security.x500.X500PrincipalBuilder;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class X509CertificateBuilderTest {

    static final PrivateKey signingKey;
    static final PublicKey publicKey;
    static final PublicKey signingPublicKey;

    static {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e);
        }
        final KeyPair keyPair1 = keyPairGenerator.generateKeyPair();
        final KeyPair keyPair2 = keyPairGenerator.generateKeyPair();
        signingKey = keyPair1.getPrivate();
        signingPublicKey = keyPair1.getPublic();
        publicKey = keyPair2.getPublic();
    }

    private static X509CertificateBuilder populateBasicCertBuilder() throws NoSuchAlgorithmException {
        X509CertificateBuilder builder = new X509CertificateBuilder();

        X500PrincipalBuilder principalBuilder = new X500PrincipalBuilder();

        principalBuilder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME, ASN1Encodable.ofUtf8String("jane")));
        final X500Principal dn = principalBuilder.build();
        builder.setIssuerDn(dn);
        builder.setSubjectDn(dn);
        builder.setSignatureAlgorithmName("SHA256withRSA");
        builder.setSigningKey(signingKey);
        builder.setPublicKey(publicKey);
        return builder;
    }

    @Test
    public void testBasic() throws Exception {
        X509CertificateBuilder builder = populateBasicCertBuilder();
        final X509Certificate certificate = builder.build();
        // basically check every field here
        assertTrue(Arrays.equals(certificate.getTBSCertificate(), builder.getTBSBytes()));
        // just to be sure!
        assertEquals("CN=jane", certificate.getIssuerX500Principal().getName());
        assertEquals("CN=jane", certificate.getSubjectX500Principal().getName());
        // if the TBS certs are equals, this should always work
        certificate.verify(signingPublicKey, KeyFactory.getInstance("RSA").getProvider());
    }

    @Test
    public void testAKIExtension() throws Exception {
        X509CertificateBuilder builder = populateBasicCertBuilder();
        builder.addExtension(new AuthorityKeyIdentifierExtension(new byte[] { 1, 2, 3, 4 }, Collections.singletonList(new GeneralName.DNSName("foo.com")), BigInteger.TEN));
        assertTrue(Arrays.equals(builder.build().getTBSCertificate(), builder.getTBSBytes()));
        builder = populateBasicCertBuilder();
        builder.addExtension(new AuthorityKeyIdentifierExtension(null, Collections.singletonList(new GeneralName.DNSName("foo.com")), BigInteger.TEN));
        assertTrue(Arrays.equals(builder.build().getTBSCertificate(), builder.getTBSBytes()));
        builder = populateBasicCertBuilder();
        builder.addExtension(new AuthorityKeyIdentifierExtension(new byte[] { 1, 2, 3, 4 }, null, BigInteger.TEN));
        assertTrue(Arrays.equals(builder.build().getTBSCertificate(), builder.getTBSBytes()));
        builder = populateBasicCertBuilder();
        builder.addExtension(new AuthorityKeyIdentifierExtension(new byte[] { 1, 2, 3, 4 }, Collections.singletonList(new GeneralName.DNSName("foo.com")), null));
        assertTrue(Arrays.equals(builder.build().getTBSCertificate(), builder.getTBSBytes()));
    }

    @Test
    public void testIssuerAltNamesExtension() throws Exception {
        X509CertificateBuilder builder = populateBasicCertBuilder();
        builder.addExtension(new IssuerAlternativeNamesExtension(true, Arrays.asList(new GeneralName.RFC822Name("elytron@wildfly.org"), new GeneralName.DNSName("elytron.wildfly.org"))));
        final X509Certificate certificate = builder.build();
        assertTrue(Arrays.equals(certificate.getTBSCertificate(), builder.getTBSBytes()));
        final Collection<List<?>> names = certificate.getIssuerAlternativeNames();
        assertEquals(2, names.size());
        final Iterator<List<?>> iterator = names.iterator();
        List<?> item = iterator.next();
        assertEquals(2, item.size());
        assertEquals(Integer.valueOf(GeneralName.RFC_822_NAME), item.get(0));
        assertEquals("elytron@wildfly.org", item.get(1));
        item = iterator.next();
        assertEquals(2, item.size());
        assertEquals(Integer.valueOf(GeneralName.DNS_NAME), item.get(0));
        assertEquals("elytron.wildfly.org", item.get(1));
    }

    @Test
    public void testSubjectAltNamesExtension() throws Exception {
        X509CertificateBuilder builder = populateBasicCertBuilder();
        builder.addExtension(new SubjectAlternativeNamesExtension(true, Arrays.asList(new GeneralName.RFC822Name("elytron@wildfly.org"), new GeneralName.DNSName("elytron.wildfly.org"))));
        final X509Certificate certificate = builder.build();
        assertTrue(Arrays.equals(certificate.getTBSCertificate(), builder.getTBSBytes()));
        final Collection<List<?>> names = certificate.getSubjectAlternativeNames();
        assertEquals(2, names.size());
        final Iterator<List<?>> iterator = names.iterator();
        List<?> item = iterator.next();
        assertEquals(2, item.size());
        assertEquals(Integer.valueOf(GeneralName.RFC_822_NAME), item.get(0));
        assertEquals("elytron@wildfly.org", item.get(1));
        item = iterator.next();
        assertEquals(2, item.size());
        assertEquals(Integer.valueOf(GeneralName.DNS_NAME), item.get(0));
        assertEquals("elytron.wildfly.org", item.get(1));
    }

    @Test
    public void testEKUExtension() throws Exception {
        X509CertificateBuilder builder = populateBasicCertBuilder();
        final List<String> usage = Arrays.asList(X500.OID_KP_CLIENT_AUTH, X500.OID_KP_SERVER_AUTH);
        builder.addExtension(new ExtendedKeyUsageExtension(true, usage));
        final X509Certificate certificate = builder.build();
        assertTrue(Arrays.equals(certificate.getTBSCertificate(), builder.getTBSBytes()));
        assertEquals(usage, certificate.getExtendedKeyUsage());
    }

    @Test
    public void testKUExtension() throws Exception {
        X509CertificateBuilder builder = populateBasicCertBuilder();
        builder.addExtension(new KeyUsageExtension(KeyUsage.digitalSignature, KeyUsage.keyAgreement, KeyUsage.keyEncipherment, KeyUsage.decipherOnly));
        final X509Certificate certificate = builder.build();
        assertTrue(Arrays.equals(certificate.getTBSCertificate(), builder.getTBSBytes()));
        final boolean[] keyUsage = certificate.getKeyUsage();
        assertNotNull(keyUsage);
        assertTrue(KeyUsage.digitalSignature.in(keyUsage));
        assertFalse(KeyUsage.nonRepudiation.in(keyUsage));
        assertTrue(KeyUsage.keyEncipherment.in(keyUsage));
        assertFalse(KeyUsage.dataEncipherment.in(keyUsage));
        assertTrue(KeyUsage.keyAgreement.in(keyUsage));
        assertFalse(KeyUsage.keyCertSign.in(keyUsage));
        assertFalse(KeyUsage.cRLSign.in(keyUsage));
        assertFalse(KeyUsage.encipherOnly.in(keyUsage));
        assertTrue(KeyUsage.decipherOnly.in(keyUsage));
    }
}
