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

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.client.config.ConfigurationXMLStreamReader;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;

import static org.junit.Assert.fail;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class XmlConfigurationTest {
    private static final Provider provider = new WildFlyElytronProvider();

    @BeforeClass
    public static void registerProvider() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testEmptyConfiguration() throws Exception {
        final byte[] xmlBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "\n" +
            "<authentication-client xmlns=\"urn:elytron:1.0\">\n" +
            "    \n" +
            "</authentication-client>\n").getBytes(StandardCharsets.UTF_8);
        final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(ConfigurationXMLStreamReader.openUri(URI.create("authentication-client.xml"), XMLInputFactory.newFactory(), new ByteArrayInputStream(xmlBytes)));
        factory.create();
    }

    @Test
    public void testRuleConfiguration() throws Exception {
        final byte[] xmlBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "\n" +
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
            "    </authentication-rules>\n" +
            "</authentication-client>\n").getBytes(StandardCharsets.UTF_8);
        final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(ConfigurationXMLStreamReader.openUri(URI.create("authentication-client.xml"), XMLInputFactory.newFactory(), new ByteArrayInputStream(xmlBytes)));
        factory.create();
    }

    @Test
    public void testConfigurationWithUndefinedCredentialStore() throws Exception {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "\n" +
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
                "</authentication-client>\n";

        final byte[] xmlBytes = xml.getBytes(StandardCharsets.UTF_8);
        try {
            final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(ConfigurationXMLStreamReader.openUri(URI.create("authentication-client.xml"), XMLInputFactory.newFactory(), new ByteArrayInputStream(xmlBytes)));
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
                "</authentication-client>\n").getBytes(StandardCharsets.UTF_8);
        try {
            final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(ConfigurationXMLStreamReader.openUri(URI.create("authentication-client.xml"), XMLInputFactory.newFactory(), new ByteArrayInputStream(xmlBytes)));
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
                "</authentication-client>\n").getBytes(StandardCharsets.UTF_8);
        try {
            final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(ConfigurationXMLStreamReader.openUri(URI.create("authentication-client.xml"), XMLInputFactory.newFactory(), new ByteArrayInputStream(xmlBytes)));
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
                "</authentication-client>\n").getBytes(StandardCharsets.UTF_8);
        try {
            final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(ConfigurationXMLStreamReader.openUri(URI.create("authentication-client.xml"), XMLInputFactory.newFactory(), new ByteArrayInputStream(xmlBytes)));
            factory.create();
        } catch (ConfigXMLParseException e) {
            return;
        }
        fail("Expected exception");
    }
}
