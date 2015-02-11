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

package org.wildfly.security.auth;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;

import org.junit.Test;
import org.wildfly.client.config.ConfigurationXMLStreamReader;
import org.wildfly.security.SecurityFactory;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class XmlConfigurationTest {

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
            "    <rules>\n" +
            "        <rule>\n" +
            "            <match-host name=\"test1\"/>\n" +
            "            <set-host name=\"localhost\"/>\n" +
            "        </rule>\n" +
            "        <rule>\n" +
            "            <match-host name=\"test2\"/>\n" +
            "            <match-userinfo name=\"fred\"/>\n" +
            "            <set-host name=\"localhost\"/>\n" +
            "            <set-user-name name=\"jane\"/>\n" +
            "        </rule>\n" +
            "    </rules>\n" +
            "</authentication-client>\n").getBytes(StandardCharsets.UTF_8);
        final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(ConfigurationXMLStreamReader.openUri(URI.create("authentication-client.xml"), XMLInputFactory.newFactory(), new ByteArrayInputStream(xmlBytes)));
        factory.create();
    }

    @Test
    public void testWrongRuleOrder() throws Exception {
        final byte[] xmlBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "\n" +
            "<authentication-client xmlns=\"urn:elytron:1.0\">\n" +
            "    <rules>\n" +
            "        <rule>\n" +
            "            <set-host name=\"localhost\"/>\n" +
            "            <match-host name=\"test1\"/>\n" +
            "        </rule>\n" +
            "        <rule>\n" +
            "            <match-host name=\"test2\"/>\n" +
            "            <set-host name=\"localhost\"/>\n" +
            "            <match-userinfo name=\"fred\"/>\n" +
            "            <set-user-name name=\"jane\"/>\n" +
            "        </rule>\n" +
            "    </rules>\n" +
            "</authentication-client>\n").getBytes(StandardCharsets.UTF_8);
        try {
            final SecurityFactory<AuthenticationContext> factory = ElytronXmlParser.parseAuthenticationClientConfiguration(ConfigurationXMLStreamReader.openUri(URI.create("authentication-client.xml"), XMLInputFactory.newFactory(), new ByteArrayInputStream(xmlBytes)));
            factory.create();
        } catch (XMLStreamException e) {
            assertEquals(e.getLocation().getLineNumber(), 7);
            return;
        }
        fail("Expected exception");
    }
}
