/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.xml.stream.XMLStreamException;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.client.config.ClientConfiguration;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.client.config.ConfigurationXMLStreamReader;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.credential.store.CredentialStoreBuilder;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class XmlConfigurationTest {

    static final String NS_ELYTRON_1_0 = "urn:elytron:1.0";

    private static final Provider provider = new WildFlyElytronProvider();

    private static Map<String, String> stores = new HashMap<>();
    private static String BASE_STORE_DIRECTORY = "target/ks-cred-stores";
    static {
        stores.put("ONE", BASE_STORE_DIRECTORY + "/ladybird_cs.jceks");
    }

    public XmlConfigurationTest() {
    }

    /**
     * Clean all Credential Stores registered in {@link XmlConfigurationTest#stores}.
     */
    public static void cleanCredentialStores() {
        File dir = new File(BASE_STORE_DIRECTORY);
        dir.mkdirs();

        for (String f: stores.values()) {
            File file = new File(f);
            file.delete();
        }
    }

    @BeforeClass
    public static void setUp() throws Exception {
        Security.addProvider(provider);
        cleanCredentialStores();
        // setup vaults that need to be complete before a test starts
        CredentialStoreBuilder.get().setKeyStoreFile(stores.get("ONE"))
                .setKeyStoreType("JCEKS")
                .setKeyStorePassword("secret_store_ONE")
                .addPassword("ladybird", "Elytron")
                .addPassword("ladybirdkey", "Elytron")
                .build();
    }

    @AfterClass
    public static void tearDown() {
        Security.removeProvider(provider.getName());
    }

    private static ConfigurationXMLStreamReader openFile(byte[] xmlBytes, String fileName) throws ConfigXMLParseException {
        return ClientConfiguration.getInstance(URI.create(fileName), () -> new ByteArrayInputStream(xmlBytes)).readConfiguration(Collections.singleton(NS_ELYTRON_1_0));
    }

    @Test
    public void testEmptyConfiguration() throws Exception {
        final byte[] xmlBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "\n" +
            "<configuration>" +
            "<authentication-client xmlns=\"urn:elytron:1.0\">\n" +
            "    \n" +
            "</authentication-client>\n" +
            "</configuration>").getBytes(StandardCharsets.UTF_8);
        final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
        factory.create();
    }

    @Test
    public void testSaslMechConfiguration() throws Exception {
        final byte[] xmlBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "\n" +
            "<configuration>" +
            "<authentication-client xmlns=\"urn:elytron:1.0\">\n" +
            "    <authentication-configurations>\n" +
            "        <configuration name=\"test-1\">\n" +
            "            <sasl-mechanism-selector selector=\"#ALL\" />\n" +
            "        </configuration>\n" +
            "        <configuration name=\"test-2\">\n" +
            "            <sasl-mechanism-selector selector=\"someName\"/>\n" +
            "        </configuration>\n" +
            "        <configuration name=\"test-3\">\n" +
            "            <sasl-mechanism-selector selector=\"someName #ALL\"/>\n" +
            "        </configuration>\n" +
            "        <configuration name=\"test-4\">\n" +
            "            <sasl-mechanism-selector selector=\"someName #ALL -JBOSS-LOCAL-USER\"/>\n" +
            "        </configuration>\n" +
            "        <configuration name=\"test-5\">\n" +
            "            <sasl-mechanism-selector selector=\"someName (! JBOSS-LOCAL-USER)\"/>\n" +
            "        </configuration>\n" +
            "        <configuration name=\"test-6\">\n" +
            "            <sasl-mechanism-selector selector=\"!#HASH(MD5)\"/>\n" +
            "        </configuration>\n" +
            "        <configuration name=\"test-7\">\n" +
            "            <sasl-mechanism-selector selector=\"#FAMILY(SCRAM)\"/>\n" +
            "        </configuration>\n" +
            "        <configuration name=\"test-8\">\n" +
            "            <sasl-mechanism-selector selector=\"(DIGEST-SHA-256||SCRAM-SHA-256) #PLUS\"/>\n" +
            "        </configuration>\n" +
            "        <configuration name=\"test-9\">\n" +
            "            <sasl-mechanism-selector selector=\"(((#HASH(SHA-256) &amp;&amp; (#PLUS) ) ) )\"/>\n" +
            "        </configuration>\n" +
            "        <configuration name=\"test-10\">\n" +
            "            <sasl-mechanism-selector selector=\"PLAIN DIGEST-MD5 ANONYMOUS JBOSS-LOCAL-USER\"/>\n" +
            "        </configuration>\n" +
            "        <configuration name=\"test-11\">\n" +
            "            <sasl-mechanism-selector selector=\"someName -PLAIN #ALL\"/>\n" +
            "        </configuration>\n" +
            "        <configuration name=\"test-12\">\n" +
            "            <sasl-mechanism-selector selector=\"-PLAIN JBOSS-LOCAL-USER PLAIN\"/>\n" +
            "        </configuration>\n" +
            "        <configuration name=\"test-13\">\n" +
            "            <sasl-mechanism-selector selector=\"-PLAIN someName -DIGEST-MD5 #ALL\"/>\n" +
            "        </configuration>\n" +
            "    </authentication-configurations>\n" +
            "    <authentication-rules>\n" +
            "        <rule use-configuration=\"test-1\">\n" +
            "            <match-host name=\"host-1\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"test-3\">\n" +
            "            <match-host name=\"host-3\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"test-4\">\n" +
            "            <match-host name=\"host-4\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"test-5\">\n" +
            "            <match-host name=\"host-5\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"test-7\">\n" +
            "            <match-host name=\"host-7\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"test-10\">\n" +
            "            <match-host name=\"host-10\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"test-11\">\n" +
            "            <match-host name=\"host-11\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"test-12\">\n" +
            "            <match-host name=\"host-12\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"test-13\">\n" +
            "            <match-host name=\"host-13\"/>\n" +
            "        </rule>\n" +
            "    </authentication-rules>\n" +
            "</authentication-client>\n" +
            "</configuration>").getBytes(StandardCharsets.UTF_8);
        final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
        AuthenticationContext ac = factory.create();

        AuthenticationConfiguration ac3 = ac.authRuleMatching(new URI("http://host-3/"), null, null).getConfiguration();
        String[] filtered = ac3.saslMechanismSelector.apply(Arrays.asList("A", "B"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"A", "B"}, filtered);

        AuthenticationConfiguration ac4 = ac.authRuleMatching(new URI("http://host-4/"), null, null).getConfiguration();
        filtered = ac4.saslMechanismSelector.apply(Arrays.asList("A", "B", "JBOSS-LOCAL-USER"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"A", "B"}, filtered);

        AuthenticationConfiguration ac5 = ac.authRuleMatching(new URI("http://host-5/"), null, null).getConfiguration();
        filtered = ac5.saslMechanismSelector.apply(Arrays.asList("A", "B", "JBOSS-LOCAL-USER"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"A", "B"}, filtered);

        // ELY-1184
        AuthenticationConfiguration ac7 = ac.authRuleMatching(new URI("http://host-7/"), null, null).getConfiguration();
        filtered = ac7.saslMechanismSelector.apply(Arrays.asList("SCRAM-SHA-1-PLUS",  "DIGEST-MD5", "SCRAM-SHA-512"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"SCRAM-SHA-1-PLUS", "SCRAM-SHA-512"}, filtered);

        // ELY-1185
        AuthenticationConfiguration ac10 = ac.authRuleMatching(new URI("http://host-10/"), null, null).getConfiguration();
        filtered = ac10.saslMechanismSelector.apply(Arrays.asList("PLAIN", "DIGEST-MD5", "JBOSS-LOCAL-USER", "ABC"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"PLAIN", "DIGEST-MD5", "JBOSS-LOCAL-USER"}, filtered);

        // ELY-1216
        AuthenticationConfiguration ac11 = ac.authRuleMatching(new URI("http://host-11/"), null, null).getConfiguration();
        filtered = ac11.saslMechanismSelector.apply(Arrays.asList("A", "B", "PLAIN"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"A", "B"}, filtered);

        AuthenticationConfiguration ac12 = ac.authRuleMatching(new URI("http://host-12/"), null, null).getConfiguration();
        filtered = ac12.saslMechanismSelector.apply(Arrays.asList("A", "B", "PLAIN", "JBOSS-LOCAL-USER"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"JBOSS-LOCAL-USER"}, filtered);

        AuthenticationConfiguration ac13 = ac.authRuleMatching(new URI("http://host-13/"), null, null).getConfiguration();
        filtered = ac13.saslMechanismSelector.apply(Arrays.asList("A", "B", "PLAIN", "DIGEST-MD5", "JBOSS-LOCAL-USER"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"A", "B", "JBOSS-LOCAL-USER"}, filtered);
    }

    @Test
    public void testRuleConfiguration() throws Exception {
        final byte[] xmlBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "\n" +
            "<configuration>" +
            "<authentication-client xmlns=\"urn:elytron:1.0\">\n" +
            "    <credential-stores>\n" +
            "        <credential-store name=\"store1\" type=\"" + KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE + "\">\n" +
            "            <protection-parameter-credentials>\n" +
            "                <clear-password password=\"1234\"/>\n" +
            "            </protection-parameter-credentials>\n" +
            "            <attributes>\n" +
            "                <attribute name=\"keyStoreType\" value=\"JCEKS\"/>\n" +
            "                <attribute name=\"create\" value=\"true\"/>\n" +
            "            </attributes>\n" +
            "        </credential-store>\n" +
            "    </credential-stores>\n" +
            "    <authentication-configurations>\n" +
            "        <configuration name=\"set-host-to-localhost\">\n" +
            "            <set-host name=\"localhost\"/>\n" +
            "        </configuration>\n" +
            "        <configuration name=\"setup-sasl\">\n" +
            "            <set-host name=\"localhost\"/>\n" +
            "            <set-protocol name=\"HTTP\"/>\n" +
            "            <set-user-name name=\"jane\"/>\n" +
            "            <sasl-mechanism-selector selector=\"#ALL\" />\n" +
            "            <set-mechanism-realm name=\"mainRealm\"/>\n" +
            "            <set-mechanism-properties>\n" +
            "                <property key=\"key-one\" value=\"value-one\"/>\n" +
            "                <property key=\"key-two\" value=\"value-two\"/>\n" +
            "            </set-mechanism-properties>\n" +
            "            <use-provider-sasl-factory/>\n" +
            "            <credentials>\n" +
            "                <credential-store-reference store=\"store1\" alias=\"jane\"/>\n" +
            "            </credentials>\n" +
            "        </configuration>\n" +
            "    </authentication-configurations>\n" +
            "    <authentication-rules>\n" +
            "        <rule use-configuration=\"set-host-to-localhost\">\n" +
            "            <match-host name=\"test1\"/>\n" +
            "            <match-no-user/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"setup-sasl\">\n" +
            "            <match-host name=\"test2\"/>\n" +
            "            <match-user name=\"fred\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"setup-sasl\">\n" +
            "            <match-port number=\"123\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"setup-sasl\">\n" +
            "            <match-user name=\"user1\"/>\n" +
            "        </rule>\n" +
            "    </authentication-rules>\n" +
            "</authentication-client>\n" +
            "</configuration>").getBytes(StandardCharsets.UTF_8);
        final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
        AuthenticationContext ac = factory.create();

        Assert.assertNull(ac.authRuleMatching(new URI("http://unknown/"), null, null)); // no match
        Assert.assertNotNull(ac.authRuleMatching(new URI("http://test1/"), null, null)); // match host
        Assert.assertNotNull(ac.authRuleMatching(new URI("http://host:123/"), null, null)); // match port
        Assert.assertNotNull(ac.authRuleMatching(new URI("http://user1@host/"), null, null)); // match user
    }

    /**
     * Test different names to be used in match-host.
     *
     * @throws Exception
     */
    @Test
    public void testMatchHostRuleConfiguration() throws Exception {
        final byte[] xmlBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "\n" +
            "<configuration>" +
            "<authentication-client xmlns=\"urn:elytron:1.0\">\n" +
            "    <authentication-configurations>\n" +
            "        <configuration name=\"set-host-to-localhost\">\n" +
            "            <set-host name=\"localhost\"/>\n" +
            "        </configuration>\n" +
            "    </authentication-configurations>\n" +
            "    <authentication-rules>\n" +
            "        <rule use-configuration=\"set-host-to-localhost\">\n" +
            "            <match-host name=\"test1\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"set-host-to-localhost\">\n" +
            "            <match-host name=\"test2\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"set-host-to-localhost\">\n" +
            "            <match-host name=\"test2.domain\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"set-host-to-localhost\">\n" +
            "            <match-host name=\"test2.domain.org\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"set-host-to-localhost\">\n" +
            "            <match-host name=\"test2.Domain.org\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"set-host-to-localhost\">\n" +
            "            <match-host name=\"test-2.domain.org\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"set-host-to-localhost\">\n" +
            "            <match-host name=\"test_2.domain.org\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"set-host-to-localhost\">\n" +
            "            <match-host name=\"2_test.domain.org\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"set-host-to-localhost\">\n" +
            "            <match-host name=\"127.0.0.1\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"set-host-to-localhost\">\n" +
            "            <match-host name=\"::1\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"set-host-to-localhost\">\n" +
            "            <match-host name=\"0:0:0:0:0:0:0:1\"/>\n" +
            "        </rule>\n" +
            "    </authentication-rules>\n" +
            "</authentication-client>\n" +
            "</configuration>").getBytes(StandardCharsets.UTF_8);
        final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
        factory.create();
    }

    @Test
    public void testConfigurationWithUndefinedCredentialStore() throws Exception {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "\n" +
                "<configuration>" +
                "<authentication-client xmlns=\"urn:elytron:1.0\">\n" +
                "    <credential-stores>\n" +
                "        <credential-store name=\"another-store\">\n" +
                "            <attributes>\n" +
                "                <attribute name=\"attr1\" value=\"value1\"/>\n" +
                "                <attribute name=\"attr2\" value=\"value2\"/>\n" +
                "                <attribute name=\"attr3\" value=\"value3\"/>\n" +
                "            </attributes>\n" +
                "        </credential-store>\n" +
                "    </credential-stores>\n" +
                "    <authentication-configurations>\n" +
                "        <configuration name=\"setup-sasl\">\n" +
                "            <set-host name=\"localhost\"/>\n" +
                "            <set-protocol name=\"HTTP\"/>\n" +
                "            <set-user-name name=\"jane\"/>\n" +
                "            <sasl-mechanism-selector selector=\"#ALL\" />\n" +
                "            <set-mechanism-realm name=\"mainRealm\"/>\n" +
                "            <set-mechanism-properties>\n" +
                "                <property key=\"key-one\" value=\"value-one\"/>\n" +
                "                <property key=\"key-two\" value=\"value-two\"/>\n" +
                "            </set-mechanism-properties>\n" +
                "            <use-provider-sasl-factory/>\n" +
                "            <credentials>\n" +
                "                <credential-store-reference store=\"store1\" alias=\"jane\"/>\n" +
                "            </credentials>\n" +
                "        </configuration>\n" +
                "    </authentication-configurations>\n" +
                "    <authentication-rules>\n" +
                "        <rule use-configuration=\"setup-sasl\">\n" +
                "            <match-host name=\"test2\"/>\n" +
                "            <match-user name=\"fred\"/>\n" +
                "        </rule>\n" +
                "    </authentication-rules>\n" +
                "</authentication-client>\n" +
                "</configuration>";

        final byte[] xmlBytes = xml.getBytes(StandardCharsets.UTF_8);
        try {
            final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
            factory.create();

        } catch (XMLStreamException e) {
            return;
        }
        fail("Expected exception");
    }

    @Test
    public void testWrongCredentialStoreConfiguration() throws Exception {
        final byte[] xmlBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "\n" +
                "<configuration>" +
                "<authentication-client xmlns=\"urn:elytron:1.0\">\n" +
                "    <credential-stores>\n" +
                "        <credential-store name=\"test1\" type=\"dummyType1\">\n" +
                "            <attributes>\n" +
                "                <attribute name=\"1attr1\" value=\"1value1\"/>\n" +
                "                <attribute name=\"1attr2\" value=\"1value2\"/>\n" +
                "                <attribute name=\"1attr3\" value=\"1value3\"/>\n" +
                "            </attributes>\n" +
                "        </credential-store>\n" +
                "        <credential-store name=\"test2\" type=\"\" provider=\"provider2\">\n" +
                "            <attributes>\n" +
                "                <attribute name=\"2attr1\" value=\"2value1\"/>\n" +
                "                <attribute name=\"2attr2\" value=\"2value2\"/>\n" +
                "                <attribute name=\"2attr3\" value=\"2value3\"/>\n" +
                "            </attributes>\n" +
                "            <attributes>\n" +
                "                <attribute name=\"attr3\" value=\"value3\"/>\n" +
                "            </attributes>\n" +
                "        </credential-store>\n" +
                "    </credential-stores>\n" +
                "</authentication-client>\n" +
                "</configuration>").getBytes(StandardCharsets.UTF_8);
        try {
            final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
            factory.create();
        } catch (XMLStreamException e) {
            return;
        }
        fail("Expected exception");
    }

    @Test
    public void testSameCredentialStoreNameInConfiguration() throws Exception {
        final byte[] xmlBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "\n" +
                "<configuration>" +
                "<authentication-client xmlns=\"urn:elytron:1.0\">\n" +
                "    <credential-stores>\n" +
                "        <credential-store name=\"test\" type=\"\">\n" +
                "            <attributes>\n" +
                "                <attribute name=\"1attr1\" value=\"1value1\"/>\n" +
                "                <attribute name=\"1attr2\" value=\"1value2\"/>\n" +
                "                <attribute name=\"1attr3\" value=\"1value3\"/>\n" +
                "            </attributes>\n" +
                "        </credential-store>\n" +
                "        <credential-store name=\"not_a_test\" type=\"dummyType3\" provider=\"provider2\"/>\n" +
                "        <credential-store name=\"test\" type=\"\">\n" +
                "            <attributes>\n" +
                "                <attribute name=\"2attr1\" value=\"2value1\"/>\n" +
                "                <attribute name=\"2attr2\" value=\"2value2\"/>\n" +
                "                <attribute name=\"2attr3\" value=\"2value3\"/>\n" +
                "            </attributes>\n" +
                "        </credential-store>\n" +
                "    </credential-stores>\n" +
                "</authentication-client>\n" +
                "</configuration>").getBytes(StandardCharsets.UTF_8);
        try {
            final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
            factory.create();
        } catch (ConfigXMLParseException e) {
            return;
        }
        fail("Expected exception");
    }

    @Test
    public void testSameAttributeInCredentialStoreConfiguration() throws Exception {
        final byte[] xmlBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "\n" +
                "<configuration>" +
                "<authentication-client xmlns=\"urn:elytron:1.0\">\n" +
                "    <credential-stores>\n" +
                "        <credential-store name=\"test1\" type=\"\">\n" +
                "            <attributes>\n" +
                "                <attribute name=\"1attr1\" value=\"1value1\"/>\n" +
                "                <attribute name=\"1attr2\" value=\"1value2\"/>\n" +
                "                <attribute name=\"1attr3\" value=\"1value3\"/>\n" +
                "            </attributes>\n" +
                "        </credential-store>\n" +
                "        <credential-store name=\"test2\" type=\"\">\n" +
                "            <attributes>\n" +
                "                <attribute name=\"2attr1\" value=\"2value1\"/>\n" +
                "                <attribute name=\"2attr2\" value=\"2value2\"/>\n" +
                "                <attribute name=\"2attr1\" value=\"2value3\"/>\n" +
                "            </attributes>\n" +
                "        </credential-store>\n" +
                "    </credential-stores>\n" +
                "</authentication-client>\n" +
                "</configuration>").getBytes(StandardCharsets.UTF_8);
        try {
            final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
            factory.create();
        } catch (ConfigXMLParseException e) {
            return;
        }
        fail("Expected exception");
    }

    /**
     * Test certificate in credentials
     *
     * @throws Exception
     */
    @Test
    public void testCertificateInCredentials() throws Exception {
        final byte[] xmlBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<configuration>\n" +
                "    <authentication-client xmlns=\"urn:elytron:1.0\">\n" +
                "        <authentication-rules>\n" +
                "            <rule use-configuration=\"default\"/>\n" +
                "        </authentication-rules>\n" +
                "        <authentication-configurations>\n" +
                "            <configuration name=\"default\">\n" +
                "                <sasl-mechanism-selector selector=\"PLAIN\"/>\n" +
                "                <credentials>\n" +
                "                    <certificate>\n" +
                "                        <private-key-pem>\n" +
                "                        -----BEGIN PRIVATE KEY-----\n" +
                "                        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCbF8HLa+3JBDIi\n" +
                "                        7bMl2hYkmgdNxec+X1c8oPPVjMaljIX0T4rQyBQRjfLd/3xDC7OSN4NXZUA8LVZf\n" +
                "                        QJcBwy38MRXS2SLg6HUa+is3E622rw0kXMxjAhfp7T6OigQS9f1GS1Fuct99m4u0\n" +
                "                        5HPOzWDfcyft99O3x68RpgsnhemrO7P/riidIGOCVY0v/V13nCvILZcnvwGwWciY\n" +
                "                        aT4jO9WqEMvi3nGHUgf3EQUCCNFxrbLrILghRp0kgPNCe/Uyz0x2iRtLa2q5Lbzk\n" +
                "                        b55jUM+OQLcYaa/bIb+MZGzVh0fqgIhTvTdcO7lRWTmVFhG/f20BBZUqNC7TD4C6\n" +
                "                        Jihr4PP9AgMBAAECggEAXz1Oh5HGmruV4jcf3S24jU99DrhqEbZQhu277radQgoy\n" +
                "                        NF4oO5+yGzmVG9iJQU7NPgwS/rcxpAKfWKz8TlvCQG0QHsOylHSLfT6FDTRrZ5TF\n" +
                "                        uD+4T1B4yPEkijmc2NvwZZtY7T9jmOnM+A+WQjeCtpUrvwmCHQhlrKvPi7zDSp/M\n" +
                "                        aBX4YMXTNe1H/ebDURFi2DcSGeGygqcvJ5itv0gM7FzmO7n0Zb5a7syp9dPEfbAG\n" +
                "                        NFVCkZ2dpwgES+v2A60wtnb/Hl1J0ceZtHtSrc5pkebFBcD9LZM9o7nia0ppkj3A\n" +
                "                        6lb4vSD5Y1q9bMjjS6Ld72i+4yJ1Eyr5mAl8ZBKcQQKBgQDzyZoWEjsc8Zjn0PCo\n" +
                "                        7inw8+7MYCBvlALUPZuANn1E7vtl0I8xmrFcqsqx3KtxjD+DB8RK3mcOh7Ce1Sk3\n" +
                "                        P8TNyVz95nV2nZ5Xrs6ayfsvFLkVPsJQe69BPuTnZZvdhCpzy8z+KcxwKfYKkFrS\n" +
                "                        7QLPRVg92iizuA1nU3gl+qn/8QKBgQCi3LW0FtFt51ObTpUcJYXFfvNeBN8DDhlo\n" +
                "                        BNQ1eXIMD/XGMhALrtttmEqrwImjmAapbr29FJBQ3+L9sdYZDFGGrKpQafoebV3l\n" +
                "                        o2n4kW75I6WzixUJi850Gy9yk1oFsale4nToZ6JHZwkBLxGJ6tRWbJLBo2DtaM2q\n" +
                "                        rKaQfK8AzQKBgGCcoIfmqa6KwEH+N6F64Pwwb45m+fO+AHEECUACWBqdatuqj1Tl\n" +
                "                        LSzAMpvSC89v+SuARHY3NTg45fHMIA1ZJDE5f7TPQ/XB+SJekFofeX/rAn485Nzo\n" +
                "                        Z0fAGQ7q4Z4j5n8FYTPIdNBukKcXFidI7jgeDx5T+pVed1Ffbtn+QKjBAoGAZSk7\n" +
                "                        JHXX+LBr2lhhfm5APYCxooDcFYW4ekglmGGrWZrASy/lj5w5aEXke/LIi/luiefj\n" +
                "                        q4MOcW3gDT1dg4mHSmQOFoz9c9DzNiTfOir8B30A/Bk0JA3XW39XZY/ppwfH8Mwx\n" +
                "                        Wfqlbjyt9zJJbqWS52vhbK4TEuS6e31qqO0JtzECgYAabc7i95RB3kYNeJUYQqdp\n" +
                "                        HqVYK6paLz2akEt1uYM9puVPUdZ9nyNHslQAvDm3XGMsxufw40KV+CHsJhLFrQZH\n" +
                "                        u+KuHmVIk8GIV95LI2klV5FwGmqLFlOPbx59g0HEswDyY8BF/7DMgH7k8uzVqnYw\n" +
                "                        7qdOZZJ4liEJYO1T3KNzOg==\n" +
                "                        -----END PRIVATE KEY-----\n" +
                "                        </private-key-pem>\n" +
                "                        <pem>\n" +
                "                        -----BEGIN CERTIFICATE-----\n" +
                "                        MIIDWTCCAkGgAwIBAgIEQFuxgzANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJD\n" +
                "                        WjEXMBUGA1UEBxMOQ3plY2ggUmVwdWJsaWMxDzANBgNVBAsTBkVBUCBRRTEQMA4G\n" +
                "                        A1UEChMHUmVkIEhhdDERMA8GA1UEAxMIY2xpZW50RG4wIBcNMTcwNjIwMDYxMzU5\n" +
                "                        WhgPMjIxNzA1MDMwNjEzNTlaMFwxCzAJBgNVBAYTAkNaMRcwFQYDVQQHEw5DemVj\n" +
                "                        aCBSZXB1YmxpYzEPMA0GA1UECxMGRUFQIFFFMRAwDgYDVQQKEwdSZWQgSGF0MREw\n" +
                "                        DwYDVQQDEwhjbGllbnREbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
                "                        AJsXwctr7ckEMiLtsyXaFiSaB03F5z5fVzyg89WMxqWMhfRPitDIFBGN8t3/fEML\n" +
                "                        s5I3g1dlQDwtVl9AlwHDLfwxFdLZIuDodRr6KzcTrbavDSRczGMCF+ntPo6KBBL1\n" +
                "                        /UZLUW5y332bi7Tkc87NYN9zJ+3307fHrxGmCyeF6as7s/+uKJ0gY4JVjS/9XXec\n" +
                "                        K8gtlye/AbBZyJhpPiM71aoQy+LecYdSB/cRBQII0XGtsusguCFGnSSA80J79TLP\n" +
                "                        THaJG0trarktvORvnmNQz45Atxhpr9shv4xkbNWHR+qAiFO9N1w7uVFZOZUWEb9/\n" +
                "                        bQEFlSo0LtMPgLomKGvg8/0CAwEAAaMhMB8wHQYDVR0OBBYEFO01U/yTywCdzOUl\n" +
                "                        hZmElDjVVcZXMA0GCSqGSIb3DQEBCwUAA4IBAQAEy+IphU7QjlWgn2kkKI6RAX6p\n" +
                "                        LAWGUlbNnfw7V131of9qz9lctRnFWazbuych/i5/oCvBj+0gyf6+PvpsfB7qlZwH\n" +
                "                        3H+jMNNoCrMp5MutLe9SYcfmvYkYGym77K4e8BiuDlfw3whE4B274nD99Y+e9CcY\n" +
                "                        FuUx3yepXY9FDo58mE05zLSXhn31uIulnUGbL1iDB1yeCFG/6J7z+AkCBPKzbgFX\n" +
                "                        3UZid9MUn45RDf8BlP6zG+px/cE2XlaZa+0LGSH9vvvVykD18cthsLHe71Q+Y2hC\n" +
                "                        vWvHG8wdujBxWg7A+H38x48i0PR6lNTsjEgTZbUgYM/SQtKvX2gNaR3z2YPU\n" +
                "                        -----END CERTIFICATE-----\n" +
                "                        </pem>\n" +
                "                    </certificate>\n" +
                "                </credentials>\n" +
                "                <providers>\n" +
                "                    <use-service-loader/>\n" +
                "                </providers>\n" +
                "            </configuration>\n" +
                "        </authentication-configurations>\n" +
                "    </authentication-client>\n" +
                "</configuration>\n").getBytes(StandardCharsets.UTF_8);
        final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
        RuleNode<AuthenticationConfiguration> ac = factory.create().authRuleMatching(new URI("http://any/"), null, null);
        assertNotNull(ac);
        X509CertificateChainPrivateCredential credential = ac.getConfiguration().getCredentialSource().getCredential(X509CertificateChainPrivateCredential.class);
        assertNotNull(credential);
        assertEquals(1216, credential.getPrivateKey().getEncoded().length);
        assertEquals(1, credential.getCertificateChain().length);
        assertEquals("CN=clientDn, O=Red Hat, OU=EAP QE, L=Czech Republic, C=CZ", credential.getCertificateChain()[0].getSubjectDN().toString());
    }

    @Test
    public void testWrongAliasInStoreSSLConfiguration() throws Exception {
        final String wrongAlias = "WrongAlias";
        final byte[] xmlBytes = ("<configuration>\n" +
    "<authentication-client xmlns=\"urn:elytron:1.0\">\n" +
        "<key-stores>\n" +
            "<key-store name=\"ladybird\" type=\"JKS\">\n" +
                "<file name=\"target/test-classes/ca/jks/ladybird.keystore\"/>\n" +
                "<key-store-clear-password password=\"Elytron\"/>\n" +
            "</key-store>\n" +
        "</key-stores>\n" +
        "<ssl-contexts>\n" +
            "<ssl-context name=\"my-ssl\">\n" +
                "<key-store-ssl-certificate key-store-name=\"ladybird\" alias=\"" + wrongAlias + "\">\n" +
                    "<key-store-clear-password password=\"Elytron\"/>\n" +
                "</key-store-ssl-certificate>\n" +
            "</ssl-context>\n" +
        "</ssl-contexts>\n" +
        "<ssl-context-rules>\n" +
        "    <rule use-ssl-context=\"my-ssl\">\n" +
        "        <match-host name=\"localhost\"/>\n" +
        "    </rule>\n" +
        "</ssl-context-rules>\n" +
    "</authentication-client>\n" +
"</configuration>").getBytes(StandardCharsets.UTF_8);
        try {
            final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
            factory.create();
        } catch (XMLStreamException e) {
            assertTrue("\"" + wrongAlias + "\" must be mentioned in the exception message", e.getMessage().contains("ELY01159: Key store entry for alias \"" + wrongAlias + "\" is missing."));
            return;
        }
        fail("Expected exception");
    }

    @Test
    public void testCredentialStoreIntegrationWithKeyStoreSSLConfiguration() throws Exception {
        final String alias = "ladybird";
        final byte[] xmlBytes = ("<configuration>\n" +
                "<authentication-client xmlns=\"urn:elytron:1.0\">\n" +
                    "<credential-stores>\n" +
                    "    <credential-store name=\"store1\" type=\"" + KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE + "\">\n" +
                    "        <protection-parameter-credentials>\n" +
                    "            <clear-password password=\"secret_store_ONE\"/>\n" +
                    "        </protection-parameter-credentials>\n" +
                    "        <attributes>\n" +
                    "            <attribute name=\"keyStoreType\" value=\"JCEKS\"/>\n" +
                    "            <attribute name=\"location\" value=\"" + stores.get("ONE") +"\"/>\n" +
                    "        </attributes>\n" +
                    "    </credential-store>\n" +
                    "</credential-stores>\n" +
                    "<key-stores>\n" +
                        "<key-store name=\"ladybird\" type=\"JKS\">\n" +
                            "<file name=\"target/test-classes/ca/jks/ladybird.keystore\"/>\n" +
                            "<credential-store-reference store=\"store1\" alias=\"ladybird\"/>\n" +
                        "</key-store>\n" +
                    "</key-stores>\n" +
                    "<ssl-contexts>\n" +
                        "<ssl-context name=\"my-ssl\">\n" +
                            "<key-store-ssl-certificate key-store-name=\"ladybird\" alias=\"" + alias + "\">\n" +
                                "<credential-store-reference store=\"store1\" alias=\"ladybirdkey\"/>\n" +
                            "</key-store-ssl-certificate>\n" +
                        "</ssl-context>\n" +
                    "</ssl-contexts>\n" +
                    "<ssl-context-rules>\n" +
                        "<rule use-ssl-context=\"my-ssl\">\n" +
                            "<match-host name=\"localhost\"/>\n" +
                        "</rule>\n" +
                    "</ssl-context-rules>\n" +
                "</authentication-client>\n" +
                "</configuration>").getBytes(StandardCharsets.UTF_8);
        final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
        factory.create();
    }

}
