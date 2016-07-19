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

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.keystore.LdapKeyStore;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.ldap.LdapName;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Date;
import java.util.Enumeration;

/**
 * Test of LDAP based Keystore
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class KeyStoreSuiteChild {

    private static KeyStore keyStore;

    @BeforeClass
    public static void createKeyStore() throws Exception {

        Attributes createAttributes = new BasicAttributes();
        createAttributes.put(new BasicAttribute("objectClass","inetOrgPerson"));
        createAttributes.put(new BasicAttribute("sn","newCert"));

        keyStore = LdapKeyStore.builder()
                .setDirContextSupplier(LdapTestSuite.dirContextFactory.create())
                .setSearchPath("ou=keystore,dc=elytron,dc=wildfly,dc=org")
                .setFilterAlias("(&(objectClass=inetOrgPerson)(cn={0}))")
                .setFilterCertificate("(&(objectClass=inetOrgPerson)(usercertificate={0}))")
                .setFilterIterate("(objectClass=inetOrgPerson)")
                .setCreatePath(new LdapName("ou=keystore,dc=elytron,dc=wildfly,dc=org"))
                .setCreateAttributes(createAttributes)
                .setCreateRdn("cn")
                .build();

        keyStore.load(null, null);
    }

    @Test
    public void testAliases() throws Exception {
        Enumeration<String> enumeration = keyStore.aliases();
        Assert.assertNotNull(enumeration);

        int count = 0;
        while(enumeration.hasMoreElements()){
            System.out.println(enumeration.nextElement());
            count++;
        }
        Assert.assertTrue(count > 0);
    }

    @Test
    public void testIs() throws Exception {
        Assert.assertTrue(keyStore.isCertificateEntry("firefly"));
        Assert.assertFalse(keyStore.isCertificateEntry("nonexisting"));
        Assert.assertTrue(keyStore.isKeyEntry("firefly"));
        Assert.assertFalse(keyStore.isKeyEntry("nonexisting"));
    }

    @Test
    public void testGetCertificate() throws Exception {
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("firefly");
        Assert.assertNotNull(cert);
        Assert.assertEquals("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Firefly", cert.getSubjectDN().toString());
    }

    @Test
    public void testGetAlias() throws Exception {
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("firefly");
        Assert.assertNotNull(cert);
        String alias = keyStore.getCertificateAlias(cert);
        Assert.assertEquals("firefly", alias);
    }

    @Test
    public void testGetCertificateChain() throws Exception {
        Certificate[] chain = keyStore.getCertificateChain("firefly");
        Assert.assertNotNull(chain);
        Assert.assertEquals(2, chain.length);
        Assert.assertEquals("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Firefly", ((X509Certificate)chain[0]).getSubjectDN().toString());
        Assert.assertEquals("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA", ((X509Certificate)chain[1]).getSubjectDN().toString());
    }

    @Test
    public void testGetKey() throws Exception {
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) keyStore.getKey("firefly", "Elytron".toCharArray());
        Assert.assertNotNull(key);
        Assert.assertEquals(BigInteger.valueOf(65537), key.getPublicExponent());
    }

    @Test
    public void testGetCreationTime() throws Exception {
        Date date = keyStore.getCreationDate("firefly");
        Assert.assertNotNull(date);
        System.out.println(date.toString());
        Assert.assertTrue(date.getTime() > 0);
    }

    @Test
    public void testSetCertificateEntryCreateRemove() throws Exception {
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("firefly");
        keyStore.setCertificateEntry("newcert", cert);
        X509Certificate newcert = (X509Certificate) keyStore.getCertificate("newcert");
        Assert.assertEquals(cert, newcert);

        Assert.assertTrue(keyStore.isCertificateEntry("newcert"));
        keyStore.deleteEntry("newcert");
        Assert.assertFalse(keyStore.isCertificateEntry("newcert"));
    }

    @Test
    public void testSetCertificateEntryUpdate() throws Exception {
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("firefly");
        Date oldDate = keyStore.getCreationDate("firefly");
        keyStore.setCertificateEntry("firefly", cert);
        X509Certificate newcert = (X509Certificate) keyStore.getCertificate("firefly");
        Assert.assertEquals(cert, newcert);
        Date newDate = keyStore.getCreationDate("firefly");
        Assert.assertNotEquals(oldDate, newDate);
    }

    @Test
    public void testSetKeyEntry() throws Exception {
        keyStore.load(null);
        Certificate[] chain = keyStore.getCertificateChain("firefly");
        Key key = keyStore.getKey("firefly", "Elytron".toCharArray());
        keyStore.setKeyEntry("newkey", key, "Elytron".toCharArray(), chain);

        Certificate[] newchain = keyStore.getCertificateChain("newkey");
        Key newkey = keyStore.getKey("newkey", "Elytron".toCharArray());
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("newkey");

        Assert.assertArrayEquals(chain, newchain);
        Assert.assertEquals(key, newkey);
        Assert.assertEquals("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Firefly", cert.getSubjectDN().toString());
    }

}
