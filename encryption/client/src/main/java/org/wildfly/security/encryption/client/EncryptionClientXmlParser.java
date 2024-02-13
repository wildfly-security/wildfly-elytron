/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.encryption.client;

import org.jboss.modules.ModuleLoadException;
import org.wildfly.client.config.ClientConfiguration;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.client.config.ConfigurationXMLStreamReader;
import org.wildfly.client.config.XMLLocation;
import org.wildfly.common.Assert;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.common.function.ExceptionUnaryOperator;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreFactory;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.provider.util.ProviderFactory;
import org.wildfly.security.provider.util.ProviderServiceLoaderSupplier;
import org.wildfly.security.provider.util.ProviderUtil;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.function.Supplier;
import java.util.Map;

import static org.wildfly.common.Assert.checkNotNullParam;

import static javax.xml.stream.XMLStreamConstants.END_ELEMENT;
import static javax.xml.stream.XMLStreamConstants.START_ELEMENT;
import static org.wildfly.security.util.XMLParserUtils.checkAttributeNamespace;
import static org.wildfly.security.util.XMLParserUtils.requireNoAttributes;
import static org.wildfly.security.util.XMLParserUtils.missingAttribute;
import static org.wildfly.security.util.XMLParserUtils.isSet;
import static org.wildfly.security.util.XMLParserUtils.setBit;
import static org.wildfly.security.util.XMLParserUtils.andThenOp;
import static org.wildfly.security.encryption.client._private.ElytronMessages.xmlLog;

import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.util.ModuleLoader;

/**
 * A parser for the Encryption Client XML schema.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */

public class EncryptionClientXmlParser {

    private static final Supplier<Provider[]> PROVIDER_SUPPLIER = ProviderFactory.getElytronProviderSupplier(EncryptionClientXmlParser.class.getClassLoader());

    private static final Supplier<Provider[]> DEFAULT_PROVIDER_SUPPLIER = ProviderUtil.aggregate(PROVIDER_SUPPLIER, ProviderUtil.INSTALLED_PROVIDERS);

    static final Map<String, Version> KNOWN_NAMESPACES;
    static final String PREFIX = "ENC";

    private enum Version {

        VERSION_1_0("urn:encryption:client:1.0", null);
        final String namespace;
        final Version parent;

        Version(String nameSpace, Version parent) {
            this.namespace = nameSpace;
            this.parent = parent;
        }
    }

    static {
        Map<String, Version> knownNamespaces = new HashMap<>();
        for (Version version : Version.values()) {
            knownNamespaces.put(version.namespace, version);
        }
        KNOWN_NAMESPACES = Collections.unmodifiableMap(knownNamespaces);
    }

    private EncryptionClientXmlParser() {
    }

    /**
     * Parse an Encryption Client configuration from a configuration discovered using the default wildfly-client-config discovery rules.
     *
     * @return the Encryption Client Context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static SecurityFactory<EncryptionClientContext> parseEncryptionClientConfiguration() throws ConfigXMLParseException {
        final ClientConfiguration clientConfiguration = ClientConfiguration.getInstance();
        if (clientConfiguration != null) try (final ConfigurationXMLStreamReader streamReader = clientConfiguration.readConfiguration(KNOWN_NAMESPACES.keySet())) {
            if (streamReader != null) {
                xmlLog.tracef("Parsing configuration from %s for namespace %s", streamReader.getUri(), streamReader.getNamespaceURI());
                return parseEncryptionClientConfiguration(streamReader);
            } else {
                if (xmlLog.isTraceEnabled()) {
                    xmlLog.tracef("No configuration found for known namespaces '%s'", namespacesToString());
                }
            }
        }
        xmlLog.trace("Falling back to no encryption client configuration.");
        return () -> EncryptionClientContext.empty();
    }

    /**
     * Parse an encryption client configuration from a resource located at a specified {@link URI}.
     *
     * @param uri the {@link URI} of the configuration.
     * @return the encryption client context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static SecurityFactory<EncryptionClientContext> parseEncryptionClientConfiguration(URI uri) throws ConfigXMLParseException {
        final ClientConfiguration clientConfiguration = ClientConfiguration.getInstance(uri);
        if (clientConfiguration != null) try (final ConfigurationXMLStreamReader streamReader = clientConfiguration.readConfiguration(KNOWN_NAMESPACES.keySet())) {
            if (streamReader != null) {
                xmlLog.tracef("Parsing configuration from %s for namespace %s", streamReader.getUri(), streamReader.getNamespaceURI());
                return parseEncryptionClientConfiguration(streamReader);
            } else {
                if (xmlLog.isTraceEnabled()) {
                    xmlLog.tracef("No configuration found for known namespaces '%s'", namespacesToString());
                }
            }
        }
        xmlLog.trace("Falling back to no encryption client configuration.");
        return () -> EncryptionClientContext.empty();
    }

    /**
     * Parse an encryption client configuration from a configuration XML reader.
     *
     * @param reader the XML stream reader
     * @return the Encryption Client Context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static SecurityFactory<EncryptionClientContext> parseEncryptionClientConfiguration(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        if (reader.hasNext()) {
            switch (reader.nextTag()) {
                case START_ELEMENT: {
                    EncryptionClientXmlParser.Version xmlVersion = KNOWN_NAMESPACES.get(checkGetElementNamespace(reader));
                    switch (reader.getLocalName()) {
                        case "encryption-client": {
                            return parseEncryptionClientType(reader, xmlVersion);
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
        xmlLog.trace("No encryption client element found, all sensitive information will need to be specified as clear text.");
        return EncryptionClientContext::empty;
    }

    static SecurityFactory<EncryptionClientContext> parseEncryptionClientType(ConfigurationXMLStreamReader reader, final EncryptionClientXmlParser.Version xmlVersion) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap = new HashMap<>();
        Map<String, EncryptedExpressionResolver.ResolverConfiguration> resolverMap = new HashMap<>();
        final DeferredSupplier<Provider[]> providersSupplier = new DeferredSupplier<>(DEFAULT_PROVIDER_SUPPLIER);
        String defaultResolverName = null;
        int foundBits = 0;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "credential-stores": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        parseCredentialStoresType(reader, xmlVersion, credentialStoresMap, providersSupplier);
                        break;
                    }
                    case "expression-resolvers": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        defaultResolverName = parseResolversType(reader, xmlVersion, resolverMap);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                assert reader.getLocalName().equals("encryption-client");
                EncryptionClientConfiguration encryptedExpressionConfig = new EncryptionClientConfiguration();

                // validate key and credential stores...
                for (Map.Entry<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> supplier : credentialStoresMap.entrySet()) {
                    encryptedExpressionConfig.credentialStoreMap.put(supplier.getKey(), supplier.getValue().get());
                }

                // configure resolvers for the encrypted expressions
                encryptedExpressionConfig.setResolverMap(resolverMap);
                encryptedExpressionConfig.encryptedExpressionResolver = new EncryptedExpressionResolver()
                        .setPrefix(PREFIX)
                        .setDefaultResolver(defaultResolverName)
                        .setResolverConfigurations(resolverMap);
                encryptedExpressionConfig.setDefaultResolverName(defaultResolverName);
                return () -> new EncryptionClientContext(encryptedExpressionConfig);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static void parseCredentialStoresType(ConfigurationXMLStreamReader reader, final EncryptionClientXmlParser.Version xmlVersion, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, final Supplier<Provider[]> providers) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount > 0) {
            throw reader.unexpectedAttribute(0);
        }
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "credential-store": {
                        parseCredentialStoreType(reader, xmlVersion, credentialStoresMap, providers);
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
     * Parse an XML element of type {@code credential-store-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param xmlVersion the version of parsed XML
     * @param credentialStoresMap the map of  credential stores to fill  @throws ConfigXMLParseException if the resource failed to be parsed
     */
    private static void parseCredentialStoreType(ConfigurationXMLStreamReader reader, final EncryptionClientXmlParser.Version xmlVersion, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, final Supplier<Provider[]> providers) throws ConfigXMLParseException {
        final XMLLocation location = reader.getLocation();
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
                    type = reader.getAttributeValueResolved(i);
                    break;
                }
                case "provider": {
                    if (provider != null) throw reader.unexpectedAttribute(i);
                    provider = reader.getAttributeValueResolved(i);
                    break;
                }
                case "name": {
                    if (name != null) throw reader.unexpectedAttribute(i);
                    name = reader.getAttributeValueResolved(i);
                    break;
                }
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        if (name == null) {
            throw missingAttribute(reader, "name");
        }

        final Map<String, String> attributesMap = new HashMap<>();
        int foundBits = 0;
        ExceptionSupplier<CredentialSource, ConfigXMLParseException> credentialSourceSupplier = null;
        DeferredSupplier<Provider[]> providersSupplier = new DeferredSupplier<>(providers);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "attributes": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        parseAttributesType(reader, xmlVersion, attributesMap);
                        break;
                    }
                    case "protection-parameter-credentials": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        credentialSourceSupplier = parseCredentialsType(reader, xmlVersion, credentialStoresMap, providersSupplier);
                        break;
                    }
                    case "providers": {
                        if (isSet(foundBits, 3)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 3);
                        Supplier<Provider[]> supplier = parseProvidersType(reader, xmlVersion);
                        if (supplier != null) {
                            providersSupplier.setSupplier(supplier);
                        }
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                if (!credentialStoresMap.containsKey(name)) {
                    ExceptionSupplier<CredentialStore, ConfigXMLParseException> credentialStoreSecurityFactory = new CredentialStoreFactory(name, type, attributesMap, provider, location, credentialSourceSupplier, providersSupplier);
                    credentialStoresMap.put(name, credentialStoreSecurityFactory);
                } else {
                    throw xmlLog.duplicateCredentialStoreName(reader, name);
                }
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    // common types

    /**
     * Parse attributes {@code attributes-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param attributesMap the map to put attributes to.
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    private static void parseAttributesType(ConfigurationXMLStreamReader reader, final EncryptionClientXmlParser.Version xmlVersion, final Map<String, String> attributesMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount > 0) {
            throw reader.unexpectedAttribute(0);
        }
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "attribute": {
                        parseAttributeType(reader, attributesMap);
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
     * Parse an attribute {@code attribute-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param attributesMap the map to put attributes to.
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    private static void parseAttributeType(ConfigurationXMLStreamReader reader, final Map<String, String> attributesMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String value = null;
        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNamespace = reader.getAttributeNamespace(i);
            if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            switch (reader.getAttributeLocalName(i)) {
                case "name": {
                    if (name != null) throw reader.unexpectedAttribute(i);
                    name = reader.getAttributeValueResolved(i);
                    break;
                }
                case "value": {
                    if (value != null) throw reader.unexpectedAttribute(i);
                    value = reader.getAttributeValueResolved(i);
//                    value = resolveElytronClientDir(value, reader);
                    break;
                }
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedContent();
            } else if (tag == END_ELEMENT) {
                if (!attributesMap.containsKey(name)) {
                    attributesMap.put(name, value);
                } else {
                    throw xmlLog.duplicateAttributeFound(reader, name);
                }
                return;
            }
            throw reader.unexpectedContent();
        }
        throw reader.unexpectedContent();
    }

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
                name = reader.getAttributeValueResolved(i);
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

    private static ExceptionSupplier<CredentialSource, ConfigXMLParseException> parseCredentialsType(final ConfigurationXMLStreamReader reader, final EncryptionClientXmlParser.Version xmlVersion, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, Supplier<Provider[]> providers) throws ConfigXMLParseException {
        ExceptionUnaryOperator<CredentialSource, ConfigXMLParseException> function = parent -> CredentialSource.NONE;
        requireNoAttributes(reader);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "clear-password": {
                        ExceptionSupplier<Password, ConfigXMLParseException> password = parseClearPassword(reader, providers);
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(new PasswordCredential(password.get()))));
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                assert reader.getLocalName().equals("credentials") || reader.getLocalName().equals("protection-parameter-credentials");
                final ExceptionUnaryOperator<CredentialSource, ConfigXMLParseException> finalFunction = function;
                return () -> finalFunction.apply(null);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    static Supplier<Provider[]> parseProvidersType(ConfigurationXMLStreamReader reader, final EncryptionClientXmlParser.Version xmlVersion) throws ConfigXMLParseException {
        requireNoAttributes(reader);

        Supplier<Provider[]> providerSupplier = null;

        int foundBits = 0;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "global": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        parseEmptyType(reader);
                        providerSupplier = providerSupplier == null ? ProviderUtil.INSTALLED_PROVIDERS : ProviderUtil.aggregate(providerSupplier, ProviderUtil.INSTALLED_PROVIDERS);
                        break;
                    }
                    case "use-service-loader": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        final String moduleName = parseModuleRefType(reader);
                        Supplier<Provider[]> serviceLoaderSupplier;
                        try {
                            serviceLoaderSupplier = (moduleName == null) ?
                                    PROVIDER_SUPPLIER :
                                    new ProviderServiceLoaderSupplier(ModuleLoader.getClassLoaderFromModule(moduleName));
                        } catch (ModuleLoadException e) {
                            throw xmlLog.xmlNoModuleFound(reader, e, moduleName);
                        }
                        providerSupplier = providerSupplier == null ? serviceLoaderSupplier : ProviderUtil.aggregate(providerSupplier, serviceLoaderSupplier);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return providerSupplier;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code module-ref-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the corresponding module name
     * @throws ConfigXMLParseException if the resource failed to be parsed or the module is not found
     */
    static String parseModuleRefType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String moduleName = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "module-name": {
                    moduleName = reader.getAttributeValueResolved(i);
                    break;
                }
                default: throw reader.unexpectedAttribute(i);
            }
        }

        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return moduleName;
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
    static ExceptionSupplier<Password, ConfigXMLParseException> parseClearPassword(ConfigurationXMLStreamReader reader, Supplier<Provider[]> providers) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        char[] password = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("password")) {
                password = reader.getAttributeValueResolved(i).toCharArray();
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
                final XMLLocation location = reader.getLocation();
                final char[] finalPassword = password;
                return () -> {
                    try {
                        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, providers);
                        return Assert.assertNotNull(factory.generatePassword(new ClearPasswordSpec(finalPassword)).castAs(ClearPassword.class));
                    } catch (InvalidKeySpecException | NoSuchAlgorithmException cause) {
                        throw xmlLog.xmlFailedToCreateCredential(location, cause);
                    }
                };
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    static String parseResolversType(ConfigurationXMLStreamReader reader, final EncryptionClientXmlParser.Version xmlVersion, final Map<String, EncryptedExpressionResolver.ResolverConfiguration> resolverMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String defaultResolver = null;

        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNamespace = reader.getAttributeNamespace(i);
            if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            switch (reader.getAttributeLocalName(i)) {
                case "default-resolver": {
                    if (defaultResolver != null) throw reader.unexpectedAttribute(i);
                    defaultResolver = reader.getAttributeValueResolved(i);
                    break;
                }
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        if (defaultResolver == null) {
            throw missingAttribute(reader, "default-resolver");
        }

        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "expression-resolver": {
                        parseResolverType(reader, resolverMap);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return defaultResolver;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedContent();
    }

    private static void parseResolverType(ConfigurationXMLStreamReader reader, final Map<String, EncryptedExpressionResolver.ResolverConfiguration> resolverMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String credentialStoreName = null;
        String alias = null;

        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNameSpace = reader.getAttributeNamespace(i);
            if (attributeNameSpace != null && !attributeNameSpace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            switch (reader.getAttributeLocalName(i)) {
                case "name": {
                    if (name!= null) throw reader.unexpectedAttribute(i);
                    name = reader.getAttributeValueResolved(i);
                    break;
                }
                case "credential-store-name": {
                    if (credentialStoreName!= null) throw reader.unexpectedAttribute(i);
                    credentialStoreName = reader.getAttributeValueResolved(i);
                    break;
                }
                case "alias": {
                    if (alias!= null) throw reader.unexpectedAttribute(i);
                    alias = reader.getAttributeValueResolved(i);
                    break;
                }
                default: {
                    throw reader.unexpectedAttribute(i);
                }
            }
        }
        if (name == null) {
            throw missingAttribute(reader, "name");
        } else if (credentialStoreName == null) {
            throw missingAttribute(reader, "credential-store-name");
        } else if (alias == null) {
            throw missingAttribute(reader, "alias");
        }

        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                if (!resolverMap.containsKey(name)) {
                    resolverMap.put(name, new EncryptedExpressionResolver.ResolverConfiguration(name, credentialStoreName, alias));
                } else {
                    throw xmlLog.duplicateAttributeFound(reader, name);
                }
                return;
            }
            throw reader.unexpectedContent();
        }
        throw reader.unexpectedContent();
    }

    private static void checkElementNamespace(final ConfigurationXMLStreamReader reader, final EncryptionClientXmlParser.Version xmlVersion) throws ConfigXMLParseException {
        if (! xmlVersion.namespace.equals(reader.getNamespaceURI())) {
            throw reader.unexpectedElement();
        }
    }

    private static String checkGetElementNamespace(final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        String namespaceUri = reader.getNamespaceURI();
        if (! KNOWN_NAMESPACES.containsKey(namespaceUri)) {
            throw reader.unexpectedElement();
        }
        return namespaceUri;
    }

    private static String namespacesToString() {
        Iterator<String> namespaceIterator = KNOWN_NAMESPACES.keySet().iterator();
        StringBuilder namespaces = new StringBuilder(namespaceIterator.next());
        while (namespaceIterator.hasNext()) {
            namespaces.append(",").append(namespaceIterator.next());
        }

        return namespaces.toString();
    }

    static final class DeferredSupplier<T>  implements Supplier<T> {

        private volatile Supplier<T> supplier;
        private T value;

        DeferredSupplier(Supplier<T> supplier) {
            checkNotNullParam("supplier", supplier);
            this.supplier = supplier;
        }

        void setSupplier(Supplier<T> supplier) {
            checkNotNullParam("supplier", supplier);
            this.supplier = supplier;
        }

        @Override
        public T get() {
            return supplier.get();
        }

    }
}
