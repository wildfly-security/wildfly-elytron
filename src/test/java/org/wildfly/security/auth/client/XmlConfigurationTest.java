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

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;

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
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class XmlConfigurationTest {
    private static final Provider provider = new WildFlyElytronProvider();

    public XmlConfigurationTest() {
    }

    @BeforeClass
    public static void registerProvider() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    private static ConfigurationXMLStreamReader openFile(byte[] xmlBytes, String fileName) throws ConfigXMLParseException {
        return ClientConfiguration.getInstance(URI.create(fileName), () -> new ByteArrayInputStream(xmlBytes)).readConfiguration(Collections.singleton(ElytronXmlParser.NS_ELYTRON_1_0));
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
            "            <allow-sasl-mechanisms names=\"someName\"/>\n" +
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
            "    </authentication-rules>\n" +
            "</authentication-client>\n" +
            "</configuration>").getBytes(StandardCharsets.UTF_8);
        final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
        AuthenticationContext ac = factory.create();

        AuthenticationConfiguration ac3 = ac.authRuleMatching(new URI("http://host-3/"), null, null, null).getConfiguration();
        String[] filtered = ac3.saslMechanismSelector.apply(Arrays.asList("A", "B"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"A", "B"}, filtered);

        AuthenticationConfiguration ac4 = ac.authRuleMatching(new URI("http://host-4/"), null, null, null).getConfiguration();
        filtered = ac4.saslMechanismSelector.apply(Arrays.asList("A", "B", "JBOSS-LOCAL-USER"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"A", "B"}, filtered);

        AuthenticationConfiguration ac5 = ac.authRuleMatching(new URI("http://host-5/"), null, null, null).getConfiguration();
        filtered = ac5.saslMechanismSelector.apply(Arrays.asList("A", "B", "JBOSS-LOCAL-USER"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"A", "B"}, filtered);

        // ELY-1184
        AuthenticationConfiguration ac7 = ac.authRuleMatching(new URI("http://host-7/"), null, null, null).getConfiguration();
        filtered = ac7.saslMechanismSelector.apply(Arrays.asList("SCRAM-SHA-1-PLUS",  "DIGEST-MD5", "SCRAM-SHA-512"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"SCRAM-SHA-1-PLUS", "SCRAM-SHA-512"}, filtered);

        // ELY-1185
        AuthenticationConfiguration ac10 = ac.authRuleMatching(new URI("http://host-10/"), null, null, null).getConfiguration();
        filtered = ac10.saslMechanismSelector.apply(Arrays.asList("PLAIN", "DIGEST-MD5", "JBOSS-LOCAL-USER", "ABC"), null).toArray(new String[]{});
        Assert.assertArrayEquals(new String[]{"PLAIN", "DIGEST-MD5", "JBOSS-LOCAL-USER"}, filtered);
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
            "            <allow-all-sasl-mechanisms />\n" +
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
            "        </rule>\n" +
            "        <rule use-configuration=\"setup-sasl\">\n" +
            "            <match-host name=\"test2\"/>\n" +
            "            <match-userinfo name=\"fred\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"setup-sasl\">\n" +
            "            <match-purpose names=\"connect\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"setup-sasl\">\n" +
            "            <match-port number=\"123\"/>\n" +
            "        </rule>\n" +
            "        <rule use-configuration=\"setup-sasl\">\n" +
            "            <match-userinfo name=\"user1\"/>\n" +
            "        </rule>\n" +
            "    </authentication-rules>\n" +
            "</authentication-client>\n" +
            "</configuration>").getBytes(StandardCharsets.UTF_8);
        final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(openFile(xmlBytes, "authentication-client.xml"));
        AuthenticationContext ac = factory.create();

        Assert.assertNull(ac.authRuleMatching(new URI("http://unknown/"), null, null, null)); // no match
        Assert.assertNotNull(ac.authRuleMatching(new URI("http://test1/"), null, null, null)); // match host
        Assert.assertNotNull(ac.authRuleMatching(new URI("http://host/"), null, null, "connect")); // match purpose
        Assert.assertNotNull(ac.authRuleMatching(new URI("http://host:123/"), null, null, null)); // match port
        Assert.assertNotNull(ac.authRuleMatching(new URI("http://user1@host/"), null, null, null)); // match user
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
                "            <allow-all-sasl-mechanisms />\n" +
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
                "            <match-userinfo name=\"fred\"/>\n" +
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
}
