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

import static javax.xml.stream.XMLStreamConstants.COMMENT;
import static javax.xml.stream.XMLStreamConstants.END_DOCUMENT;
import static javax.xml.stream.XMLStreamConstants.END_ELEMENT;
import static javax.xml.stream.XMLStreamConstants.PROCESSING_INSTRUCTION;
import static javax.xml.stream.XMLStreamConstants.START_ELEMENT;
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
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;

import org.jboss.modules.Module;
import org.jboss.modules.ModuleIdentifier;
import org.jboss.modules.ModuleLoadException;
import org.wildfly.client.config.ClientConfiguration;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.client.config.ConfigurationXMLStreamReader;
import org.wildfly.common.function.ExceptionUnaryOperator;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.OneTimeSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.util.ElytronAuthenticator;
import org.wildfly.security.auth.util.RegexNameRewriter;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.keystore.PasswordEntry;
import org.wildfly.security.keystore.WrappingPasswordKeyStore;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.util.ServiceLoaderSaslClientFactory;
import org.wildfly.security.ssl.CipherSuiteSelector;
import org.wildfly.security.ssl.ProtocolSelector;
import org.wildfly.security.ssl.SSLContextBuilder;
import org.wildfly.security.util.ServiceLoaderSupplier;
import org.wildfly.security.x500.X500;

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
        if (clientConfiguration != null) try (final ConfigurationXMLStreamReader streamReader = clientConfiguration.readConfiguration(Collections.singleton(NS_ELYTRON_1_0))) {
            return parseAuthenticationClientConfiguration(streamReader);
        } else {
            return new FixedSecurityFactory<>(AuthenticationContext.EMPTY);
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
        if (reader.hasNext()) {
            switch (reader.nextTag()) {
                case START_ELEMENT: {
                    checkElementNamespace(reader);
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
                    throw reader.unexpectedContent();
                }
            }
        }
        // Try legacy configuration next
        final ServiceLoader<LegacyConfiguration> loader = ServiceLoader.load(LegacyConfiguration.class, ElytronXmlParser.class.getClassLoader());
        final Iterator<LegacyConfiguration> iterator = loader.iterator();
        final List<LegacyConfiguration> configs = new ArrayList<>();
        for (;;) try {
            if (! iterator.hasNext()) break;
            configs.add(iterator.next());
        } catch (ServiceConfigurationError ignored) {}
        return () -> {
            for (LegacyConfiguration config : configs) {
                final AuthenticationContext context = config.getConfiguredAuthenticationContext();
                if (context != null) return context;
            }
            return AuthenticationContext.EMPTY;
        };
    }

    // authentication client types

    /**
     * Parse an XML element of type {@code authentication-client-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the authentication context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static SecurityFactory<AuthenticationContext> parseAuthenticationClientType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        SecurityFactory<AuthenticationContext> futureContext = null;
        requireNoAttributes(reader);
        SecurityFactory<RuleNode<AuthenticationConfiguration>> authFactory = null;
        SecurityFactory<RuleNode<SecurityFactory<SSLContext>>> sslFactory = null;
        Map<String, SecurityFactory<KeyStore>> keyStoresMap = new HashMap<>();
        Map<String, SecurityFactory<SSLContext>> sslContextsMap = new HashMap<>();
        boolean keyStores = false;
        boolean sslContexts = false;
        boolean netAuthenticator = false;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "rules": {
                        if (authFactory != null) {
                            throw reader.unexpectedElement();
                        }
                        authFactory = parseAuthenticationClientRulesType(reader, keyStoresMap);
                        break;
                    }
                    case "ssl-context-rules": {
                        if (sslFactory != null) {
                            throw reader.unexpectedElement();
                        }
                        sslFactory = parseSslContextRulesType(reader, sslContextsMap);
                        break;
                    }
                    case "ssl-contexts": {
                        if (sslContexts) {
                            throw reader.unexpectedElement();
                        }
                        sslContexts = true;
                        parseSslContextsType(reader, sslContextsMap, keyStoresMap);
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
                final SecurityFactory<RuleNode<AuthenticationConfiguration>> finalAuthFactory = authFactory;
                final SecurityFactory<RuleNode<SecurityFactory<SSLContext>>> finalSslFactory = sslFactory;
                return () -> new AuthenticationContext(finalAuthFactory != null ? finalAuthFactory.create() : null, finalSslFactory != null ? finalSslFactory.create() : null);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static void parseSslContextsType(final ConfigurationXMLStreamReader reader, final Map<String, SecurityFactory<SSLContext>> sslContextsMap, final Map<String, SecurityFactory<KeyStore>> keyStoresMap) throws ConfigXMLParseException {
        final int count = reader.getAttributeCount();
        if (count == 0) {
            throw reader.missingRequiredAttribute(null, "name");
        }
        checkAttributeNamespace(reader, 0);
        if (! reader.getAttributeLocalName(0).equals("name")) {
            throw reader.unexpectedAttribute(0);
        }
        if (count > 1) {
            throw reader.unexpectedAttribute(1);
        }
        final String name = reader.getAttributeValue(1);
        if (sslContextsMap.containsKey(name)) {
            throw xmlLog.duplicateSslContextName(name, reader);
        }
        int foundBits = 0;
        Supplier<Provider[]> providersSupplier = Security::getProviders;
        String providerName = null;
        CipherSuiteSelector cipherSuiteSelector = null;
        ProtocolSelector protocolSelector = null;
        PrivateKeyKeyStoreEntryCredentialFactory credentialFactory = null;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "key-store-ssl-certificate": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        credentialFactory = new PrivateKeyKeyStoreEntryCredentialFactory(parseKeyStoreRefType(reader, keyStoresMap));
                        break;
                    }
                    case "ssl-cipher-suite": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        cipherSuiteSelector = parseCipherSuiteSelectorType(reader);
                        break;
                    }
                    case "ssl-protocol": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        protocolSelector = parseProtocolSelectorNamesType(reader);
                        break;
                    }
                    case "provider-name": {
                        if (isSet(foundBits, 3)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 3);
                        providerName = parseNameType(reader);
                        break;
                    }
                    // these two are a <choice> which is why they share a bit #; you can have only one of them
                    case "use-system-providers": {
                        if (isSet(foundBits, 4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 4);
                        parseEmptyType(reader);
                        // no action; this is a way of explicitly specifying the default
                        break;
                    }
                    case "use-module-providers": {
                        if (isSet(foundBits, 4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 4);
                        final Module module = parseModuleRefType(reader);
                        providersSupplier = new ServiceLoaderSupplier<>(Provider.class, module.getClassLoader());
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag != END_ELEMENT) {
                throw reader.unexpectedContent();
            } else {
                // ready to register!
                final Supplier<Provider[]> finalProvidersSupplier = providersSupplier;
                final ProtocolSelector finalProtocolSelector = protocolSelector;
                final CipherSuiteSelector finalCipherSuiteSelector = cipherSuiteSelector;
                final String finalProviderName = providerName;
                final PrivateKeyKeyStoreEntryCredentialFactory finalCredentialFactory = credentialFactory;
                sslContextsMap.put(name, () -> {
                    final SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
                    sslContextBuilder.setClientMode(true);
                    if (finalCipherSuiteSelector != null) {
                        sslContextBuilder.setCipherSuiteSelector(finalCipherSuiteSelector);
                    }
                    if (finalProtocolSelector != null) {
                        sslContextBuilder.setProtocolSelector(finalProtocolSelector);
                    }
                    if (finalCredentialFactory != null) {
                        final ConfigurationKeyManager.Builder builder = new ConfigurationKeyManager.Builder();
                        final X509CertificateChainPrivateCredential privateCredential = finalCredentialFactory.create();
                        builder.addCredential(privateCredential);
                        sslContextBuilder.setKeyManager(builder.build());
                    }
                    sslContextBuilder.setProviderName(finalProviderName);
                    sslContextBuilder.setProviderSupplier(finalProvidersSupplier);
                    sslContextBuilder.setUseCipherSuitesOrder(true);
                    return sslContextBuilder.build().create();
                });
                return;
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code ssl-context-rules-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param sslContextsMap the SSL contexts map
     * @return the SSL context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static SecurityFactory<RuleNode<SecurityFactory<SSLContext>>> parseSslContextRulesType(final ConfigurationXMLStreamReader reader, final Map<String, SecurityFactory<SSLContext>> sslContextsMap) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        final List<ExceptionUnaryOperator<RuleNode<SecurityFactory<SSLContext>>, GeneralSecurityException>> rulesList = new ArrayList<>();
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "rule": {
                        rulesList.add(parseSslContextRuleType(reader, sslContextsMap));
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return new OneTimeSecurityFactory<>(() -> {
                    RuleNode<SecurityFactory<SSLContext>> node = null;
                    final ListIterator<ExceptionUnaryOperator<RuleNode<SecurityFactory<SSLContext>>, GeneralSecurityException>> iterator = rulesList.listIterator(rulesList.size());
                    // iterate backwards to build the singly-linked list in constant time
                    while (iterator.hasPrevious()) {
                        node = iterator.previous().apply(node);
                    }
                    return node;
                });
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    static ExceptionUnaryOperator<RuleNode<SecurityFactory<SSLContext>>, GeneralSecurityException> parseSslContextRuleType(final ConfigurationXMLStreamReader reader, final Map<String, SecurityFactory<SSLContext>> sslContextsMap) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        if (! reader.hasNext()) {
            throw reader.unexpectedDocumentEnd();
        }
        int tag = reader.nextTag();
        if (tag == START_ELEMENT) {
            final MatchRule rule = parseMatchRuleGroup(reader);
            tag = reader.getEventType();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "use-ssl-context": {
                        final String name = parseNameType(reader);
                        if (! reader.hasNext()) throw reader.unexpectedDocumentEnd();
                        if (reader.nextTag() != END_ELEMENT) throw reader.unexpectedElement();
                        return next -> {
                            final SecurityFactory<SSLContext> factory = sslContextsMap.get(name);
                            if (factory == null) throw xmlLog.unknownSslContextSpecified();
                            return new RuleNode<>(next, rule, factory);
                        };
                    }
                    case "use-default-ssl-context": {
                        parseEmptyType(reader);
                        if (! reader.hasNext()) throw reader.unexpectedDocumentEnd();
                        if (reader.nextTag() != END_ELEMENT) throw reader.unexpectedElement();
                        return next -> new RuleNode<>(next, rule, SSLContext::getDefault);
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            }
        }
        throw reader.missingRequiredElement(NS_ELYTRON_1_0, "use-ssl-context/use-default-ssl-context");
    }

    /**
     * Parse an XML element of type {@code authentication-client-rules-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param keyStoresMap the map of key stores to use
     * @return the authentication configuration factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static SecurityFactory<RuleNode<AuthenticationConfiguration>> parseAuthenticationClientRulesType(ConfigurationXMLStreamReader reader, final Map<String, SecurityFactory<KeyStore>> keyStoresMap) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        final List<ExceptionUnaryOperator<RuleNode<AuthenticationConfiguration>, GeneralSecurityException>> rulesList = new ArrayList<>();
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "rule": {
                        rulesList.add(parseAuthenticationClientRuleType(reader, keyStoresMap));
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return new OneTimeSecurityFactory<>(() -> {
                    RuleNode<AuthenticationConfiguration> node = null;
                    final ListIterator<ExceptionUnaryOperator<RuleNode<AuthenticationConfiguration>, GeneralSecurityException>> iterator = rulesList.listIterator(rulesList.size());
                    // iterate backwards to build the singly-linked list in constant time
                    while (iterator.hasPrevious()) {
                        node = iterator.previous().apply(node);
                    }
                    return node;
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
     * @param keyStoresMap the map of key stores to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionUnaryOperator<RuleNode<AuthenticationConfiguration>, GeneralSecurityException> parseAuthenticationClientRuleType(ConfigurationXMLStreamReader reader, final Map<String, SecurityFactory<KeyStore>> keyStoresMap) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        ExceptionUnaryOperator<AuthenticationConfiguration, GeneralSecurityException> configuration = ignored -> AuthenticationConfiguration.EMPTY;
        if (! reader.hasNext()) {
            throw reader.unexpectedDocumentEnd();
        }
        final MatchRule rule = parseMatchRuleGroup(reader);
        int foundBits = 0;
        int tag = reader.getEventType();
        for (;;) {
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    // -- set --
                    case "set-host": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        final String hostName = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useHost(hostName));
                        break;
                    }
                    case "set-port": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        final int port = parsePortType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.usePort(port));
                        break;
                    }
                    // these two are a <choice> which is why they share a bit #; you can have only one of them
                    case "set-user-name": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        final String userName = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useName(userName));
                        break;
                    }
                    case "set-anonymous": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        parseEmptyType(reader);
                        configuration = andThenOp(configuration, AuthenticationConfiguration::useAnonymous);
                        break;
                    }
                    case "set-mechanism-realm": {
                        if (isSet(foundBits, 3)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 3);
                        final String realm = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useRealm(realm));
                        break;
                    }
                    case "rewrite-user-name-regex": {
                        if (isSet(foundBits, 4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 4);
                        final NameRewriter nameRewriter = parseRegexSubstitutionType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.rewriteUser(nameRewriter));
                        break;
                    }
                    case "set-mechanism-properties": {
                        if (isSet(foundBits, 5)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 5);
                        final Map<String, String> mechanismProperties = parsePropertiesType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useMechanismProperties(mechanismProperties));
                        break;
                    }
                    case "allow-all-sasl-mechanisms": {
                        if (isSet(foundBits, 6)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 6);
                        parseEmptyType(reader);
                        configuration = andThenOp(configuration, AuthenticationConfiguration::allowAllSaslMechanisms);
                        break;
                    }
                    case "allow-sasl-mechanisms": {
                        if (isSet(foundBits, 7)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 7);
                        final String[] names = parseNamesType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.allowSaslMechanisms(names));
                        break;
                    }
                    case "forbid-sasl-mechanisms": {
                        if (isSet(foundBits, 8)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 8);
                        final String[] names = parseNamesType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.forbidSaslMechanisms(names));
                        break;
                    }
                    case "key-store-credential": {
                        if (isSet(foundBits, 9)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 9);
                        final SecurityFactory<KeyStore.Entry> factory = parseKeyStoreRefType(reader, keyStoresMap);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useKeyStoreCredential(factory.create()));
                        break;
                    }
                    case "clear-password": {
                        if (isSet(foundBits, 10)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 10);
                        final char[] password = parseClearPassword(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.usePassword(password));
                        break;
                    }
                    case "set-authorization-name": {
                        if (isSet(foundBits, 11)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 11);
                        final String authName = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useAuthorizationName(authName));
                        break;
                    }
                    // these two are a <choice> which is why they share a bit #; you can have only one of them
                    case "use-system-providers": {
                        if (isSet(foundBits, 12)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 12);
                        parseEmptyType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useProviders(Security::getProviders));
                        break;
                    }
                    case "use-module-providers": {
                        if (isSet(foundBits, 12)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 12);
                        final Module module = parseModuleRefType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useProviders(new ServiceLoaderSupplier<Provider>(Provider.class, module.getClassLoader())));
                        break;
                    }
                    // these two are a <choice> which is why they share a bit #; you can have only one of them
                    case "use-provider-sasl-factory": {
                        if (isSet(foundBits, 13)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 13);
                        parseEmptyType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useSaslClientFactoryFromProviders());
                        break;
                    }
                    case "use-module-sasl-factory": {
                        if (isSet(foundBits, 13)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 13);
                        final Module module = parseModuleRefType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useSaslClientFactory(new ServiceLoaderSaslClientFactory(module.getClassLoader())));
                        break;
                    }
                    case "set-protocol": {
                        if (isSet(foundBits, 14)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 14);
                        final String protocol = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useProtocol(protocol));
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                final ExceptionUnaryOperator<AuthenticationConfiguration, GeneralSecurityException> finalConfiguration = configuration;
                return next -> new RuleNode<>(next, rule, finalConfiguration.apply(AuthenticationConfiguration.EMPTY));
            } else {
                throw reader.unexpectedContent();
            }
            if (! reader.hasNext()) {
                throw reader.unexpectedDocumentEnd();
            }
            tag = reader.nextTag();
        }
    }

    /**
     * Parse the XML match-rule group.  On return, the reader will be positioned either at a start tag for an element
     * that is not included in this group, or at an end tag.
     *
     * @param reader the XML reader
     * @return the parsed match rule
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static MatchRule parseMatchRuleGroup(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        MatchRule rule = MatchRule.ALL;
        int foundBits = 0;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    // -- match --
                    case "match-no-userinfo": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        parseEmptyType(reader);
                        rule = rule.matchNoUser();
                        break;
                    }
                    case "match-userinfo": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        rule = rule.matchUser(parseNameType(reader));
                        break;
                    }
                    case "match-protocol": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        rule = rule.matchProtocol(parseNameType(reader));
                        break;
                    }
                    case "match-host": {
                        if (isSet(foundBits, 3)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 3);
                        rule = rule.matchHost(parseNameType(reader));
                        break;
                    }
                    case "match-path": {
                        if (isSet(foundBits, 4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 4);
                        rule = rule.matchPath(parseNameType(reader));
                        break;
                    }
                    case "match-port": {
                        if (isSet(foundBits, 5)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 5);
                        rule = rule.matchPort(parsePortType(reader));
                        break;
                    }
                    case "match-urn": {
                        if (isSet(foundBits, 6)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 6);
                        rule = rule.matchUrnName(parseNameType(reader));
                        break;
                    }
                    case "match-domain": {
                        if (isSet(foundBits, 7)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 7);
                        rule = rule.matchLocalSecurityDomain(parseNameType(reader));
                        break;
                    }
                    case "match-abstract-type": {
                        if (isSet(foundBits, 8)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 8);
                        rule = parseMatchAbstractType(rule, reader);
                        break;
                    }
                    case "match-purpose": {
                        if (isSet(foundBits, 9)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 9);
                        rule = rule.matchPurposes(parseNamesType(reader));
                        break;
                    }
                    default: {
                        return rule;
                    }
                }
            } else {
                return rule;
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static MatchRule parseMatchAbstractType(final MatchRule rule, final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String authority = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "name": name = reader.getAttributeValue(i); break;
                case "authority": authority = reader.getAttributeValue(i); break;
                default: throw reader.unexpectedAttribute(i);
            }
        }
        if (! reader.hasNext()) throw reader.unexpectedDocumentEnd();
        if (reader.nextTag() != END_ELEMENT) throw reader.unexpectedElement();
        return name == null && authority == null ? rule : rule.matchAbstractType(name, authority);
    }

    private static boolean isSet(int var, int bit) {
        return (var & 1 << bit) != 0;
    }

    private static int setBit(int var, int bit) {
        return var | 1 << bit;
    }

    private static <T> UnaryOperator<T> andThenOp(UnaryOperator<T> first, UnaryOperator<T> second) {
        return t -> second.apply(first.apply(t));
    }

    private static <T, E extends Exception> ExceptionUnaryOperator<T, E> andThenOp(ExceptionUnaryOperator<T, E> first, ExceptionUnaryOperator<T, E> second) {
        return t -> second.apply(first.apply(t));
    }

    /**
     * Parse an XML element of type {@code key-stores-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param keyStoresMap the map of key stores to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static void parseKeyStoresType(ConfigurationXMLStreamReader reader, final Map<String, SecurityFactory<KeyStore>> keyStoresMap) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
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
    static void parseKeyStoreType(ConfigurationXMLStreamReader reader, final Map<String, SecurityFactory<KeyStore>> keyStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String type = null;
        String provider = null;
        Boolean wrap = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
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
                case "wrap-passwords": {
                    if (wrap != null) throw reader.unexpectedAttribute(i);
                    wrap = Boolean.valueOf(Boolean.parseBoolean(reader.getAttributeValue(i)));
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
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "key-store-credential": {
                        // group 2
                        if (! gotSource || gotCredential) {
                            throw reader.unexpectedElement();
                        }
                        gotCredential = true;
                        final SecurityFactory<KeyStore.Entry> entryFactory = parseKeyStoreRefType(reader, keyStoresMap);
                        passwordFactory = new OneTimeSecurityFactory<>(() -> {
                            final KeyStore.Entry entry = entryFactory.create();
                            if (entry instanceof PasswordEntry) {
                                final Password password = ((PasswordEntry) entry).getPassword();
                                final PasswordFactory passwordFactory1 = PasswordFactory.getInstance(password.getAlgorithm());
                                final ClearPasswordSpec passwordSpec = passwordFactory1.getKeySpec(password, ClearPasswordSpec.class);
                                return passwordSpec.getEncodedPassword();
                            }
                            return null;
                        });
                        break;
                    }
                    case "key-store-clear-password": {
                        // group 2
                        if (! gotSource || gotCredential) {
                            throw reader.unexpectedElement();
                        }
                        gotCredential = true;
                        passwordFactory = new FixedSecurityFactory<>(parseClearPassword(reader));
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
                SecurityFactory<KeyStore> keyStoreFactory = new KeyStoreCreateFactory(provider, type);
                if (wrap == Boolean.TRUE) {
                    keyStoreFactory = new PasswordKeyStoreFactory(keyStoreFactory);
                }
                if (fileSource != null) {
                    keyStoreFactory = new FileLoadingKeyStoreFactory(keyStoreFactory, passwordFactory, fileSource);
                } else if (resourceSource != null) {
                    keyStoreFactory = new ResourceLoadingKeyStoreFactory(keyStoreFactory, passwordFactory, resourceSource);
                } else if (uriSource != null) {
                    keyStoreFactory = new URILoadingKeyStoreFactory(keyStoreFactory, passwordFactory, uriSource);
                } else {
                    // not reachable
                    throw new IllegalStateException();
                }
                keyStoresMap.put(name, new OneTimeSecurityFactory<KeyStore>(keyStoreFactory));
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
    static SecurityFactory<KeyStore.Entry> parseKeyStoreRefType(ConfigurationXMLStreamReader reader, final Map<String, SecurityFactory<KeyStore>> keyStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String keyStoreName = null;
        String alias = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
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
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "key-store-credential": {
                        if (keyStoreCredential != null) throw reader.unexpectedElement();
                        keyStoreCredential = parseKeyStoreRefType(reader, keyStoresMap);
                        break;
                    }
                    case "key-store-clear-password": {
                        if (keyStoreCredential != null) throw reader.unexpectedElement();
                        keyStoreCredential = new FixedSecurityFactory<>(new PasswordEntry(ClearPassword.createRaw("clear", parseClearPassword(reader))));
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                final SecurityFactory<KeyStore.Entry> finalKeyStoreCredential = keyStoreCredential;
                final String finalKeyStoreName = keyStoreName;
                return new KeyStoreEntrySecurityFactory(() -> {
                    final SecurityFactory<KeyStore> keyStoreSecurityFactory = keyStoresMap.get(finalKeyStoreName);
                    if (keyStoreSecurityFactory == null) {
                        throw xmlLog.unknownKeyStoreSpecified();
                    }
                    return keyStoreSecurityFactory.create();
                }, alias, keyStoreCredential == null ? null : () -> {
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
                });
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    // common types

    /**
     * Parse an XML element of type {@code empty-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static void parseEmptyType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        requireNoAttributes(reader);
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
    static String parseNameType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        return parseNameType(reader, false);
    }

    /**
     * Parse an XML element of type {@code name-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param optional is the name attribute optional?
     * @return the parsed name
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static String parseNameType(ConfigurationXMLStreamReader reader, boolean optional) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("name")) {
                name = reader.getAttributeValue(i);
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (name == null && !optional) {
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
    static int parsePortType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        int number = -1;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
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
    static NameRewriter parseRegexSubstitutionType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        Pattern pattern = null;
        String replacement = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
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
    static String[] parseNamesType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String[] names = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
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
    static URI parseUriType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        URI uri = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
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

    /**
     * Parse an XML element of type {@code ssl-cipher-selector-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the parsed cipher suite selector
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static CipherSuiteSelector parseCipherSuiteSelectorType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        CipherSuiteSelector selector = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("selector")) {
                selector = CipherSuiteSelector.fromString(reader.getAttributeValue(i));
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (selector == null) {
            throw missingAttribute(reader, "selector");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return selector;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code names} which yields a protocol selector from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the parsed protocol selector
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ProtocolSelector parseProtocolSelectorNamesType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        ProtocolSelector selector = ProtocolSelector.empty();
        for (String name : parseNamesType(reader)) {
            selector = selector.add(name);
        }
        return selector;
    }

    /**
     * Parse an XML element of type {@code module-ref-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the corresponding module
     * @throws ConfigXMLParseException if the resource failed to be parsed or the module is not found
     */
    static Module parseModuleRefType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String slot = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("name")) {
                name = reader.getAttributeValue(i);
            } else if (reader.getAttributeLocalName(i).equals("slot")) {
                slot = reader.getAttributeValue(i);
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
                final ModuleIdentifier identifier = ModuleIdentifier.create(name, slot);
                try {
                    return Module.getModuleFromCallerModuleLoader(identifier);
                } catch (ModuleLoadException e) {
                    throw xmlLog.noModuleFound(reader, e, identifier);
                }
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code clear-password-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the clear password characters
     * @throws ConfigXMLParseException if the resource failed to be parsed or the module is not found
     */
    static char[] parseClearPassword(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        char[] password = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("password")) {
                password = reader.getAttributeValue(i).toCharArray();
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (password == null) {
            throw missingAttribute(reader, "password");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return password;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    static Map<String, String> parsePropertiesType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        if (reader.getAttributeCount() > 0) {
            throw reader.unexpectedAttribute(0);
        }

        Map<String, String> propertiesMap = new HashMap<>();

        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "property":
                        final int attributeCount = reader.getAttributeCount();
                        String key = null;
                        String value = null;
                        for (int i = 0; i < attributeCount; i++) {
                            checkAttributeNamespace(reader, i);
                            switch (reader.getAttributeLocalName(i)) {
                                case "key":
                                    if (key != null)
                                        throw reader.unexpectedAttribute(i);
                                    key = reader.getAttributeValue(i);
                                    break;
                                case "value":
                                    if (value != null)
                                        throw reader.unexpectedAttribute(i);
                                    value = reader.getAttributeValue(i);
                                    break;
                                default:
                                    throw reader.unexpectedAttribute(i);
                            }
                        }
                        if (key == null) {
                            throw missingAttribute(reader, "key");
                        }
                        if (value == null) {
                            throw missingAttribute(reader, "value");
                        }
                        propertiesMap.put(key, value);
                        if (reader.hasNext()) {
                            final int innerTag = reader.nextTag();
                            if (innerTag == START_ELEMENT) {
                                throw reader.unexpectedElement();
                            } else if (innerTag == END_ELEMENT) {
                            } else {
                                throw reader.unexpectedContent();
                            }
                        } else {
                            throw reader.unexpectedDocumentEnd();
                        }

                        break;
                    default:
                        throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return propertiesMap;
            } else {
                throw reader.unexpectedContent();
            }
        }

        throw reader.unexpectedDocumentEnd();
    }

    // util

    private static void checkElementNamespace(final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        if (! reader.getNamespaceURI().equals(NS_ELYTRON_1_0)) {
            throw reader.unexpectedElement();
        }
    }

    private static void checkAttributeNamespace(final ConfigurationXMLStreamReader reader, final int idx) throws ConfigXMLParseException {
        final String attributeNamespace = reader.getAttributeNamespace(idx);
        if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
            throw reader.unexpectedAttribute(idx);
        }
    }

    private static void requireNoAttributes(final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount > 0) {
            throw reader.unexpectedAttribute(0);
        }
    }

    private static ConfigXMLParseException missingAttribute(final ConfigurationXMLStreamReader reader, final String name) {
        return reader.missingRequiredAttribute(null, name);
    }

    private static ConfigXMLParseException invalidPortNumber(final ConfigurationXMLStreamReader reader, final int index) {
        return xmlLog.xmlInvalidPortNumber(reader, reader.getAttributeValue(index), reader.getAttributeLocalName(index), reader.getName());
    }

    static final class KeyStoreCreateFactory implements SecurityFactory<KeyStore> {
        private final String provider;
        private final String type;

        KeyStoreCreateFactory(final String provider, final String type) {
            this.provider = provider;
            this.type = type;
        }

        public KeyStore create() throws GeneralSecurityException {
            return provider == null ? KeyStore.getInstance(type) : KeyStore.getInstance(type, provider);
        }
    }

    static final class PasswordKeyStoreFactory implements SecurityFactory<KeyStore> {
        private final SecurityFactory<KeyStore> delegateFactory;

        PasswordKeyStoreFactory(final SecurityFactory<KeyStore> delegateFactory) {
            this.delegateFactory = delegateFactory;
        }

        public KeyStore create() throws GeneralSecurityException {
            return new WrappingPasswordKeyStore(delegateFactory.create());
        }
    }

    abstract static class AbstractLoadingKeyStoreFactory implements SecurityFactory<KeyStore> {

        protected final SecurityFactory<KeyStore> delegateFactory;
        protected final SecurityFactory<char[]> passwordFactory;

        protected AbstractLoadingKeyStoreFactory(final SecurityFactory<KeyStore> delegateFactory, final SecurityFactory<char[]> passwordFactory) {
            this.delegateFactory = delegateFactory;
            this.passwordFactory = passwordFactory;
        }

        public KeyStore create() throws GeneralSecurityException {
            KeyStore keyStore = delegateFactory.create();
            try (InputStream fis = createStream()) {
                keyStore.load(fis, passwordFactory == null ? null : passwordFactory.create());
            } catch (IOException e) {
                throw xmlLog.failedToLoadKeyStoreData(e);
            }
            return keyStore;
        }

        abstract InputStream createStream() throws IOException;
    }

    static final class FileLoadingKeyStoreFactory extends AbstractLoadingKeyStoreFactory {

        private final String fileName;

        FileLoadingKeyStoreFactory(final SecurityFactory<KeyStore> delegateFactory, final SecurityFactory<char[]> passwordFactory, final String fileName) {
            super(delegateFactory, passwordFactory);
            this.fileName = fileName;
        }

        InputStream createStream() throws FileNotFoundException {
            return new FileInputStream(fileName);
        }
    }

    static final class ResourceLoadingKeyStoreFactory extends AbstractLoadingKeyStoreFactory {

        private final String resourceName;

        ResourceLoadingKeyStoreFactory(final SecurityFactory<KeyStore> delegateFactory, final SecurityFactory<char[]> passwordFactory, final String resourceName) {
            super(delegateFactory, passwordFactory);
            this.resourceName = resourceName;
        }

        InputStream createStream() throws IOException {
            final ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
            final InputStream stream = contextClassLoader.getResourceAsStream(resourceName);
            if (stream == null) throw new FileNotFoundException(resourceName);
            return stream;
        }
    }

    static final class URILoadingKeyStoreFactory extends AbstractLoadingKeyStoreFactory {
        private final URI uri;

        URILoadingKeyStoreFactory(final SecurityFactory<KeyStore> delegateFactory, final SecurityFactory<char[]> passwordFactory, final URI uri) {
            super(delegateFactory, passwordFactory);
            this.uri = uri;
        }

        InputStream createStream() throws IOException {
            return uri.toURL().openStream();
        }
    }

    static final class PrivateKeyKeyStoreEntryCredentialFactory implements SecurityFactory<X509CertificateChainPrivateCredential> {
        private final SecurityFactory<KeyStore.Entry> entrySecurityFactory;

        PrivateKeyKeyStoreEntryCredentialFactory(final SecurityFactory<KeyStore.Entry> entrySecurityFactory) {
            this.entrySecurityFactory = entrySecurityFactory;
        }

        public X509CertificateChainPrivateCredential create() throws GeneralSecurityException {
            final KeyStore.Entry entry = entrySecurityFactory.create();
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                final X509Certificate[] certificateChain = X500.asX509CertificateArray(privateKeyEntry.getCertificateChain());
                return new X509CertificateChainPrivateCredential(privateKeyEntry.getPrivateKey(), certificateChain);
            }
            throw xmlLog.invalidKeyStoreEntryType("unknown", KeyStore.PrivateKeyEntry.class, entry.getClass());
        }
    }
}
