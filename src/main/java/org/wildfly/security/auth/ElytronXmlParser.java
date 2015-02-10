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

import static javax.xml.stream.XMLStreamConstants.*;
import static org.wildfly.security._private.ElytronMessages.xmlLog;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.wildfly.client.config.ClientConfiguration;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.client.config.ConfigurationXMLStreamReader;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.OneTimeSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.util.ElytronAuthenticator;
import org.wildfly.security.auth.util.NameRewriter;
import org.wildfly.security.auth.util.RegexNameRewriter;
import org.wildfly.security.keystore.PasswordEntry;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * A parser for the Elytron XML schema.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ElytronXmlParser {

    private static final String NS_ELYTRON_1_0 = "urn:elytron:1.0";

    // authentication client document

    /**
     * Parse a Elytron authentication client configuration from a resource in the given class loader.
     *
     * @return the authentication context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static SecurityFactory<AuthenticationContext> parseAuthenticationClientConfiguration() throws ConfigXMLParseException {
        final ClientConfiguration clientConfiguration = ClientConfiguration.getInstance();
        try (final ConfigurationXMLStreamReader streamReader = clientConfiguration.readConfiguration(Collections.singleton(NS_ELYTRON_1_0))) {
            return parseAuthenticationClientConfiguration(streamReader);
        }
    }

    /**
     * Parse a Elytron authentication client configuration from a configuration XML reader.
     *
     * @param reader the XML stream reader
     * @return the authentication context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static SecurityFactory<AuthenticationContext> parseAuthenticationClientConfiguration(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        while (reader.hasNext()) {
            switch (reader.next()) {
                case COMMENT:
                case PROCESSING_INSTRUCTION: {
                    break;
                }
                case START_DOCUMENT: {
                    // expected
                    break;
                }
                case START_ELEMENT: {
                    switch (reader.getNamespaceURI()) {
                        case NS_ELYTRON_1_0: break;
                        default: throw reader.unexpectedElement();
                    }
                    switch (reader.getLocalName()) {
                        case "authentication-client": {
                            SecurityFactory<AuthenticationContext> futureContext = parseAuthenticationClientType(reader);
                            while (reader.hasNext()) {
                                switch (reader.next()) {
                                    case COMMENT:
                                    case PROCESSING_INSTRUCTION: {
                                        break;
                                    }
                                    case END_DOCUMENT: {
                                        return futureContext;
                                    }
                                    default: {
                                        if (reader.isWhiteSpace()) break;
                                        throw reader.unexpectedElement();
                                    }
                                }
                            }
                            return futureContext;
                        }
                        default: {
                            throw reader.unexpectedElement();
                        }
                    }
                }
                default: {
                    if (reader.isWhiteSpace()) break;
                    throw reader.unexpectedContent();
                }
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    // authentication client types

    /**
     * Parse an XML element of type {@code authentication-client-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the authentication context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static SecurityFactory<AuthenticationContext> parseAuthenticationClientType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        SecurityFactory<AuthenticationContext> futureContext = null;
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount > 0) {
            throw reader.unexpectedAttribute(0);
        }
        boolean rules = false;
        boolean keyStores = false;
        boolean netAuthenticator = false;
        Map<String, SecurityFactory<KeyStore>> keyStoresMap = new HashMap<>();
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                switch (reader.getNamespaceURI()) {
                    case "urn:elytron:1.0": break;
                    default: throw reader.unexpectedElement();
                }
                switch (reader.getLocalName()) {
                    case "rules": {
                        if (rules) {
                            throw reader.unexpectedElement();
                        }
                        rules = true;
                        futureContext = parseAuthenticationClientRulesType(reader, keyStoresMap);
                        break;
                    }
                    case "key-stores": {
                        if (keyStores) {
                            throw reader.unexpectedElement();
                        }
                        keyStores = true;
                        parseKeyStoresType(reader, keyStoresMap);
                        break;
                    }
                    case "net-authenticator": {
                        if (netAuthenticator) {
                            throw reader.unexpectedElement();
                        }
                        netAuthenticator = true;
                        parseEmptyType(reader);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                if (netAuthenticator) {
                    Authenticator.setDefault(new ElytronAuthenticator());
                }
                return futureContext == null ? new FixedSecurityFactory<>(AuthenticationContext.EMPTY) : futureContext;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code authentication-client-rules-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param keyStoresMap the map of key stores to use
     * @return the authentication context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static SecurityFactory<AuthenticationContext> parseAuthenticationClientRulesType(ConfigurationXMLStreamReader reader, final Map<String, SecurityFactory<KeyStore>> keyStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount > 0) {
            throw reader.unexpectedAttribute(0);
        }
        final Map<String, SecurityFactory<RuleConfigurationPair>> rulesMap = new HashMap<>();
        final List<SecurityFactory<RuleConfigurationPair>> rulesList = new ArrayList<>();
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                switch (reader.getNamespaceURI()) {
                    case "urn:elytron:1.0": break;
                    default: throw reader.unexpectedElement();
                }
                switch (reader.getLocalName()) {
                    case "rule": {
                        parseAuthenticationClientRuleType(reader, rulesList, rulesMap, keyStoresMap);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return new OneTimeSecurityFactory<>(new SecurityFactory<AuthenticationContext>() {
                    public AuthenticationContext create() throws GeneralSecurityException {
                        AuthenticationContext context = AuthenticationContext.EMPTY;
                        for (SecurityFactory<RuleConfigurationPair> pairFactory : rulesList) {
                            final RuleConfigurationPair pair = pairFactory.create();
                            context = context.with(pair.getMatchRule(), pair.getConfiguration());
                        }
                        return context;
                    }
                });
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code authentication-client-rule-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param rulesList the list to which rule-configuration pairs should be appended
     * @param keyStoresMap the map of key stores to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static void parseAuthenticationClientRuleType(ConfigurationXMLStreamReader reader, final List<SecurityFactory<RuleConfigurationPair>> rulesList, final Map<String, SecurityFactory<RuleConfigurationPair>> rulesMap, final Map<String, SecurityFactory<KeyStore>> keyStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String _extends = null;
        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNamespace = reader.getAttributeNamespace(i);
            if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            switch (reader.getAttributeLocalName(i)) {
                case "extends": {
                    if (_extends != null) throw reader.unexpectedAttribute(i);
                    _extends = reader.getAttributeValue(i);
                    break;
                }
                case "name": {
                    if (name != null) throw reader.unexpectedAttribute(i);
                    name = reader.getAttributeValue(i);
                    break;
                }
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        SecurityFactory<MatchRule> rule;
        SecurityFactory<AuthenticationConfiguration> configuration;
        if (_extends == null) {
            rule = new FixedSecurityFactory<>(MatchRule.ALL);
            configuration = new FixedSecurityFactory<>(AuthenticationConfiguration.EMPTY);
        } else {
            final String ext = _extends;
            rule = new SecurityFactory<MatchRule>() {
                public MatchRule create() throws GeneralSecurityException {
                    final SecurityFactory<RuleConfigurationPair> factory = rulesMap.get(ext);
                    if (factory == null) throw new IllegalArgumentException("Missing reference in extends");
                    return factory.create().getMatchRule();
                }
            };
            configuration = new SecurityFactory<AuthenticationConfiguration>() {
                public AuthenticationConfiguration create() throws GeneralSecurityException {
                    final SecurityFactory<RuleConfigurationPair> factory = rulesMap.get(ext);
                    if (factory == null) throw new IllegalArgumentException("Missing reference in extends");
                    return factory.create().getConfiguration();
                }
            };
        }
        boolean gotConfig = false;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                switch (reader.getNamespaceURI()) {
                    case "urn:elytron:1.0": break;
                    default: throw reader.unexpectedElement();
                }
                switch (reader.getLocalName()) {
                    // -- match --
                    case "match-no-userinfo": {
                        if (gotConfig) throw reader.unexpectedElement();
                        parseEmptyType(reader);
                        final SecurityFactory<MatchRule> parentRule = rule;
                        rule = new SecurityFactory<MatchRule>() {
                            public MatchRule create() throws GeneralSecurityException {
                                return parentRule.create().matchNoUser();
                            }
                        };
                        break;
                    }
                    case "match-userinfo": {
                        if (gotConfig) throw reader.unexpectedElement();
                        final String userName = parseNameType(reader);
                        final SecurityFactory<MatchRule> parentRule = rule;
                        rule = new SecurityFactory<MatchRule>() {
                            public MatchRule create() throws GeneralSecurityException {
                                return parentRule.create().matchUser(userName);
                            }
                        };
                        break;
                    }
                    case "match-protocol": {
                        if (gotConfig) throw reader.unexpectedElement();
                        final String protoName = parseNameType(reader);
                        final SecurityFactory<MatchRule> parentRule = rule;
                        rule = new SecurityFactory<MatchRule>() {
                            public MatchRule create() throws GeneralSecurityException {
                                return parentRule.create().matchProtocol(protoName);
                            }
                        };
                        break;
                    }
                    case "match-host": {
                        if (gotConfig) throw reader.unexpectedElement();
                        final String hostName = parseNameType(reader);
                        final SecurityFactory<MatchRule> parentRule = rule;
                        rule = new SecurityFactory<MatchRule>() {
                            public MatchRule create() throws GeneralSecurityException {
                                return parentRule.create().matchHost(hostName);
                            }
                        };
                        break;
                    }
                    case "match-path": {
                        if (gotConfig) throw reader.unexpectedElement();
                        final String pathName = parseNameType(reader);
                        final SecurityFactory<MatchRule> parentRule = rule;
                        rule = new SecurityFactory<MatchRule>() {
                            public MatchRule create() throws GeneralSecurityException {
                                return parentRule.create().matchPath(pathName);
                            }
                        };
                        break;
                    }
                    case "match-port": {
                        if (gotConfig) throw reader.unexpectedElement();
                        final int port = parsePortType(reader);
                        final SecurityFactory<MatchRule> parentRule = rule;
                        rule = new SecurityFactory<MatchRule>() {
                            public MatchRule create() throws GeneralSecurityException {
                                return parentRule.create().matchPort(port);
                            }
                        };
                        break;
                    }
                    case "match-urn": {
                        if (gotConfig) throw reader.unexpectedElement();
                        final String urnString = parseNameType(reader);
                        final SecurityFactory<MatchRule> parentRule = rule;
                        rule = new SecurityFactory<MatchRule>() {
                            public MatchRule create() throws GeneralSecurityException {
                                return parentRule.create().matchUrnName(urnString);
                            }
                        };
                        break;
                    }
                    case "match-domain": {
                        if (gotConfig) throw reader.unexpectedElement();
                        final String domainName = parseNameType(reader);
                        final SecurityFactory<MatchRule> parentRule = rule;
                        rule = new SecurityFactory<MatchRule>() {
                            public MatchRule create() throws GeneralSecurityException {
                                return parentRule.create().matchLocalSecurityDomain(domainName);
                            }
                        };
                        break;
                    }

                    // -- set --
                    case "set-host": {
                        gotConfig = true;
                        final String hostName = parseNameType(reader);
                        final SecurityFactory<AuthenticationConfiguration> parentConfig = configuration;
                        configuration = new SecurityFactory<AuthenticationConfiguration>() {
                            public AuthenticationConfiguration create() throws GeneralSecurityException {
                                return parentConfig.create().useHost(hostName);
                            }
                        };
                        break;
                    }
                    case "set-port": {
                        gotConfig = true;
                        final int port = parsePortType(reader);
                        final SecurityFactory<AuthenticationConfiguration> parentConfig = configuration;
                        configuration = new SecurityFactory<AuthenticationConfiguration>() {
                            public AuthenticationConfiguration create() throws GeneralSecurityException {
                                return parentConfig.create().usePort(port);
                            }
                        };
                        break;
                    }
                    case "set-user-name": {
                        gotConfig = true;
                        final String userName = parseNameType(reader);
                        final SecurityFactory<AuthenticationConfiguration> parentConfig = configuration;
                        configuration = new SecurityFactory<AuthenticationConfiguration>() {
                            public AuthenticationConfiguration create() throws GeneralSecurityException {
                                return parentConfig.create().useName(userName);
                            }
                        };
                        break;
                    }
                    case "set-anonymous": {
                        gotConfig = true;
                        parseEmptyType(reader);
                        final SecurityFactory<AuthenticationConfiguration> parentConfig = configuration;
                        configuration = new SecurityFactory<AuthenticationConfiguration>() {
                            public AuthenticationConfiguration create() throws GeneralSecurityException {
                                return parentConfig.create().useAnonymous();
                            }
                        };
                        break;
                    }
                    case "rewrite-user-name-regex": {
                        gotConfig = true;
                        final NameRewriter nameRewriter = parseRegexSubstitutionType(reader);
                        final SecurityFactory<AuthenticationConfiguration> parentConfig = configuration;
                        configuration = new SecurityFactory<AuthenticationConfiguration>() {
                            public AuthenticationConfiguration create() throws GeneralSecurityException {
                                return parentConfig.create().rewriteUser(nameRewriter);
                            }
                        };
                        break;
                    }
                    case "require-sasl-mechanisms": {
                        gotConfig = true;
                        final String[] names = parseNamesType(reader);
                        final SecurityFactory<AuthenticationConfiguration> parentConfig = configuration;
                        configuration = new SecurityFactory<AuthenticationConfiguration>() {
                            public AuthenticationConfiguration create() throws GeneralSecurityException {
                                return parentConfig.create().allowSaslMechanisms(names);
                            }
                        };
                        break;
                    }
                    case "forbid-sasl-mechanisms": {
                        gotConfig = true;
                        final String[] names = parseNamesType(reader);
                        final SecurityFactory<AuthenticationConfiguration> parentConfig = configuration;
                        configuration = new SecurityFactory<AuthenticationConfiguration>() {
                            public AuthenticationConfiguration create() throws GeneralSecurityException {
                                return parentConfig.create().forbidSaslMechanisms(names);
                            }
                        };
                        break;
                    }
                    case "key-store-credential": {
                        gotConfig = true;
                        final SecurityFactory<KeyStore.Entry> factory = parseKeyStoreRefType(reader, keyStoresMap);
                        final SecurityFactory<AuthenticationConfiguration> parentConfig = configuration;
                        configuration = new SecurityFactory<AuthenticationConfiguration>() {
                            public AuthenticationConfiguration create() throws GeneralSecurityException {
                                return parentConfig.create().useKeyStoreCredential(factory.create());
                            }
                        };
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                final OneTimeSecurityFactory<MatchRule> finalRule = new OneTimeSecurityFactory<MatchRule>(rule);
                final OneTimeSecurityFactory<AuthenticationConfiguration> finalConfig = new OneTimeSecurityFactory<AuthenticationConfiguration>(configuration);
                final SecurityFactory<RuleConfigurationPair> finalPair = new SecurityFactory<RuleConfigurationPair>() {
                    public RuleConfigurationPair create() throws GeneralSecurityException {
                        return new RuleConfigurationPair(finalRule.create(), finalConfig.create());
                    }
                };
                rulesList.add(finalPair);
                if (name != null) {
                    rulesMap.put(name, finalPair);
                }
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
    }

    /**
     * Parse an XML element of type {@code key-stores-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param keyStoresMap the map of key stores to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static void parseKeyStoresType(ConfigurationXMLStreamReader reader, final Map<String, SecurityFactory<KeyStore>> keyStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount > 0) {
            throw reader.unexpectedAttribute(0);
        }
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                switch (reader.getNamespaceURI()) {
                    case "urn:elytron:1.0": break;
                    default: throw reader.unexpectedElement();
                }
                switch (reader.getLocalName()) {
                    case "key-store": {
                        parseKeyStoreType(reader, keyStoresMap);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code key-store-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param keyStoresMap the map of key stores to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static void parseKeyStoreType(ConfigurationXMLStreamReader reader, final Map<String, SecurityFactory<KeyStore>> keyStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String type = null;
        String provider = null;
        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNamespace = reader.getAttributeNamespace(i);
            if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            switch (reader.getAttributeLocalName(i)) {
                case "type": {
                    if (type != null) throw reader.unexpectedAttribute(i);
                    type = reader.getAttributeValue(i);
                    break;
                }
                case "provider": {
                    if (provider != null) throw reader.unexpectedAttribute(i);
                    provider = reader.getAttributeValue(i);
                    break;
                }
                case "name": {
                    if (name != null) throw reader.unexpectedAttribute(i);
                    name = reader.getAttributeValue(i);
                    break;
                }
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        if (type == null) {
            throw missingAttribute(reader, "type");
        }
        if (name == null) {
            throw missingAttribute(reader, "name");
        }
        SecurityFactory<char[]> passwordFactory = null;
        boolean gotSource = false;
        boolean gotCredential = false;

        String fileSource = null;
        String resourceSource = null;
        URI uriSource = null;

        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                switch (reader.getNamespaceURI()) {
                    case "urn:elytron:1.0": break;
                    default: throw reader.unexpectedElement();
                }
                switch (reader.getLocalName()) {
                    case "key-store-credential": {
                        // group 2
                        if (! gotSource || gotCredential) {
                            throw reader.unexpectedElement();
                        }
                        gotCredential = true;
                        final SecurityFactory<KeyStore.Entry> entryFactory = parseKeyStoreRefType(reader, keyStoresMap);
                        passwordFactory = new OneTimeSecurityFactory<>(new SecurityFactory<char[]>() {
                            public char[] create() throws GeneralSecurityException {
                                final KeyStore.Entry entry = entryFactory.create();
                                if (entry instanceof PasswordEntry) {
                                    final Password password = ((PasswordEntry) entry).getPassword();
                                    final PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm());
                                    final ClearPasswordSpec passwordSpec = passwordFactory.getKeySpec(password, ClearPasswordSpec.class);
                                    return passwordSpec.getEncodedPassword();
                                }
                                return null;
                            }
                        });
                        break;
                    }
                    case "file": {
                        // group 1
                        if (gotSource) {
                            throw reader.unexpectedElement();
                        }
                        gotSource = true;
                        fileSource = parseNameType(reader);
                        break;
                    }
                    case "resource": {
                        // group 1
                        if (gotSource) {
                            throw reader.unexpectedElement();
                        }
                        gotSource = true;
                        resourceSource = parseNameType(reader);
                        break;
                    }
                    case "uri": {
                        // group 1
                        if (gotSource) {
                            throw reader.unexpectedElement();
                        }
                        gotSource = true;
                        uriSource = parseUriType(reader);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                if (fileSource != null) {
                    keyStoresMap.put(name, new OneTimeSecurityFactory<KeyStore>(new FileKeyStoreFactory(provider, type, passwordFactory, fileSource)));
                } else if (resourceSource != null) {
                    keyStoresMap.put(name, new OneTimeSecurityFactory<KeyStore>(new ResourceKeyStoreFactory(provider, type, passwordFactory, resourceSource)));
                } else if (uriSource != null) {
                    keyStoresMap.put(name, new OneTimeSecurityFactory<KeyStore>(new URIKeyStoreFactory(provider, type, passwordFactory, uriSource)));
                } else {
                    // not reachable
                    throw new IllegalStateException();
                }
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code kwy-store-ref-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param keyStoresMap the map of key stores to use
     * @return the key store entry factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static SecurityFactory<KeyStore.Entry> parseKeyStoreRefType(ConfigurationXMLStreamReader reader, final Map<String, SecurityFactory<KeyStore>> keyStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String keyStoreName = null;
        String alias = null;
        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNamespace = reader.getAttributeNamespace(i);
            if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            switch (reader.getAttributeLocalName(i)) {
                case "key-store-name": {
                    if (keyStoreName != null) throw reader.unexpectedAttribute(i);
                    keyStoreName = reader.getAttributeValue(i);
                    break;
                }
                case "alias": {
                    if (alias != null) throw reader.unexpectedAttribute(i);
                    alias = reader.getAttributeValue(i);
                    break;
                }
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        if (keyStoreName == null) {
            throw missingAttribute(reader, "key-store-name");
        }
        if (alias == null) {
            throw missingAttribute(reader, "alias");
        }
        SecurityFactory<KeyStore.Entry> keyStoreCredential = null;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                switch (reader.getNamespaceURI()) {
                    case "urn:elytron:1.0": break;
                    default: throw reader.unexpectedElement();
                }
                switch (reader.getLocalName()) {
                    case "key-store-credential": {
                        if (keyStoreCredential != null) throw reader.unexpectedElement();
                        keyStoreCredential = parseKeyStoreRefType(reader, keyStoresMap);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                final SecurityFactory<KeyStore.Entry> finalKeyStoreCredential = keyStoreCredential;
                final String finalKeyStoreName = keyStoreName;
                return new KeyStoreEntrySecurityFactory(new SecurityFactory<KeyStore>() {
                    public KeyStore create() throws GeneralSecurityException {
                        final SecurityFactory<KeyStore> keyStoreSecurityFactory = keyStoresMap.get(finalKeyStoreName);
                        if (keyStoreSecurityFactory == null) {
                            throw new IllegalArgumentException("Unknown key store specified");
                        }
                        return keyStoreSecurityFactory.create();
                    }
                }, alias, keyStoreCredential == null ? null : new SecurityFactory<KeyStore.ProtectionParameter>() {
                    public KeyStore.ProtectionParameter create() throws GeneralSecurityException {
                        final KeyStore.Entry entry = finalKeyStoreCredential.create();
                        if (entry instanceof PasswordEntry) {
                            final Password password = ((PasswordEntry) entry).getPassword();
                            final PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm());
                            final ClearPasswordSpec spec = passwordFactory.getKeySpec(password, ClearPasswordSpec.class);
                            return new KeyStore.PasswordProtection(spec.getEncodedPassword());
                        } else if (entry instanceof KeyStore.SecretKeyEntry) {
                            final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                            final SecretKeyFactory instance = SecretKeyFactory.getInstance(secretKey.getAlgorithm());
                            final SecretKeySpec keySpec = (SecretKeySpec) instance.getKeySpec(secretKey, SecretKeySpec.class);
                            final byte[] encoded = keySpec.getEncoded();
                            return encoded == null ? null : new KeyStore.PasswordProtection(new String(encoded, StandardCharsets.UTF_8).toCharArray());
                        } else {
                            return null;
                        }
                    }
                });
            } else {
                throw reader.unexpectedContent();
            }
        }
        return null;
    }

    // common types

    /**
     * Parse an XML element of type {@code empty-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static void parseEmptyType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount > 0) {
            throw reader.unexpectedAttribute(0);
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code name-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the parsed name
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static String parseNameType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNamespace = reader.getAttributeNamespace(i);
            if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            if (reader.getAttributeLocalName(i).equals("name")) {
                name = reader.getAttributeValue(i);
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (name == null) {
            throw missingAttribute(reader, "name");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return name;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code port-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the port number (1-65535 inclusive)
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static int parsePortType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        int number = -1;
        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNamespace = reader.getAttributeNamespace(i);
            if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            if (reader.getAttributeLocalName(i).equals("number")) {
                String s = reader.getAttributeValue(i);
                try {
                    number = Integer.parseInt(s);
                } catch (NumberFormatException ignored) {
                    throw invalidPortNumber(reader, i);
                }
                if (number < 1 || number > 65535) {
                    throw invalidPortNumber(reader, i);
                }
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (number == -1) {
            throw missingAttribute(reader, "number");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return number;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code regex-substitution-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the regular expression based name rewriter
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static NameRewriter parseRegexSubstitutionType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        Pattern pattern = null;
        String replacement = null;
        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNamespace = reader.getAttributeNamespace(i);
            if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            if (reader.getAttributeLocalName(i).equals("pattern")) {
                pattern = Pattern.compile(reader.getAttributeValue(i));
            } else if (reader.getAttributeLocalName(i).equals("replacement")) {
                replacement = reader.getAttributeValue(i);
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (pattern == null) {
            throw missingAttribute(reader, "pattern");
        }
        if (replacement == null) {
            throw missingAttribute(reader, "replacement");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return new RegexNameRewriter(pattern, replacement, true);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code names-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the array of parsed names
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static String[] parseNamesType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String[] names = null;
        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNamespace = reader.getAttributeNamespace(i);
            if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            if (reader.getAttributeLocalName(i).equals("names")) {
                String s = reader.getAttributeValue(i);
                names = s.trim().split("\\s+");
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (names == null) {
            throw missingAttribute(reader, "names");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return names;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code uri-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the parsed URI
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static URI parseUriType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        URI uri = null;
        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNamespace = reader.getAttributeNamespace(i);
            if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            if (reader.getAttributeLocalName(i).equals("uri")) {
                uri = reader.getURIAttributeValue(i);
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (uri == null) {
            throw missingAttribute(reader, "uri");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return uri;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    // util

    private static ConfigXMLParseException missingAttribute(final ConfigurationXMLStreamReader reader, final String name) {
        return reader.missingRequiredAttribute(null, name);
    }

    private static ConfigXMLParseException invalidPortNumber(final ConfigurationXMLStreamReader reader, final int index) {
        return xmlLog.xmlInvalidPortNumber(reader, reader.getAttributeValue(index), reader.getAttributeLocalName(index), reader.getName());
    }

    abstract static class AbstractKeyStoreFactory implements SecurityFactory<KeyStore> {

        protected final String provider;
        protected final String type;
        protected final SecurityFactory<char[]> passwordFactory;

        AbstractKeyStoreFactory(final String provider, final String type, final SecurityFactory<char[]> passwordFactory) {
            this.provider = provider;
            this.passwordFactory = passwordFactory;
            this.type = type;
        }

        public KeyStore create() throws GeneralSecurityException {
            KeyStore keyStore = provider == null ? KeyStore.getInstance(type) : KeyStore.getInstance(type, provider);
            try (InputStream fis = createStream()) {
                keyStore.load(fis, passwordFactory.create());
            } catch (IOException e) {
                throw new KeyStoreException("Failed to load keystore data", e);
            }
            return keyStore;
        }

        abstract InputStream createStream() throws IOException;
    }

    static final class FileKeyStoreFactory extends AbstractKeyStoreFactory {

        private final String fileName;

        FileKeyStoreFactory(final String provider, final String type, final SecurityFactory<char[]> passwordFactory, final String fileName) {
            super(provider, type, passwordFactory);
            this.fileName = fileName;
        }

        InputStream createStream() throws FileNotFoundException {
            return new FileInputStream(fileName);
        }
    }

    static final class ResourceKeyStoreFactory extends AbstractKeyStoreFactory {

        private final String resourceName;

        ResourceKeyStoreFactory(final String provider, final String type, final SecurityFactory<char[]> passwordFactory, final String resourceName) {
            super(provider, type, passwordFactory);
            this.resourceName = resourceName;
        }

        InputStream createStream() throws IOException {
            final ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
            final InputStream stream = contextClassLoader.getResourceAsStream(resourceName);
            if (stream == null) throw new FileNotFoundException(resourceName);
            return stream;
        }
    }

    static final class URIKeyStoreFactory extends AbstractKeyStoreFactory {
        private final URI uri;

        URIKeyStoreFactory(final String provider, final String type, final SecurityFactory<char[]> passwordFactory, final URI uri) {
            super(provider, type, passwordFactory);
            this.uri = uri;
        }

        InputStream createStream() throws IOException {
            return uri.toURL().openStream();
        }
    }
}
