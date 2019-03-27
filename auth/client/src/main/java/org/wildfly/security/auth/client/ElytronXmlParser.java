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

import static javax.xml.stream.XMLStreamConstants.END_ELEMENT;
import static javax.xml.stream.XMLStreamConstants.START_ELEMENT;
import static org.wildfly.common.Assert.checkMinimumParameter;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.auth.client.ElytronMessages.xmlLog;
import static org.wildfly.security.provider.util.ProviderUtil.INSTALLED_PROVIDERS;
import static org.wildfly.security.provider.util.ProviderUtil.findProvider;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.function.IntFunction;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.stream.Location;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import org.wildfly.client.config.ClientConfiguration;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.client.config.ConfigurationXMLStreamReader;
import org.wildfly.client.config.XMLLocation;
import org.wildfly.common.Assert;
import org.wildfly.common.function.ExceptionBiFunction;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.common.function.ExceptionUnaryOperator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.asn1.OidsUtil;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.util.ElytronAuthenticator;
import org.wildfly.security.auth.util.RegexNameRewriter;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.credential.KeyPairCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.PublicKeyCredential;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.source.impl.CredentialStoreCredentialSource;
import org.wildfly.security.credential.source.impl.KeyStoreCredentialSource;
import org.wildfly.security.credential.source.impl.LocalKerberosCredentialSource;
import org.wildfly.security.credential.source.OAuth2CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.keystore.AliasFilter;
import org.wildfly.security.keystore.FilteringKeyStore;
import org.wildfly.security.keystore.KeyStoreUtil;
import org.wildfly.security.keystore.PasswordEntry;
import org.wildfly.security.keystore.WrappingPasswordKeyStore;
import org.wildfly.security.mechanism.gssapi.GSSCredentialSecurityFactory;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.MaskedPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.MaskedPasswordSpec;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.pem.PemEntry;
import org.wildfly.security.provider.util.ProviderFactory;
import org.wildfly.security.provider.util.ProviderServiceLoaderSupplier;
import org.wildfly.security.provider.util.ProviderUtil;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.util.ServiceLoaderSaslClientFactory;
import org.wildfly.security.ssl.CipherSuiteSelector;
import org.wildfly.security.ssl.ProtocolSelector;
import org.wildfly.security.ssl.SSLContextBuilder;
import org.wildfly.security.ssl.X509RevocationTrustManager;

/**
 * A parser for the Elytron XML schema.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ElytronXmlParser {

    private static final Supplier<Provider[]> ELYTRON_PROVIDER_SUPPLIER = ProviderFactory.getElytronProviderSupplier(ElytronXmlParser.class.getClassLoader());

    private static final Supplier<Provider[]> DEFAULT_PROVIDER_SUPPLIER = ProviderUtil.aggregate(ELYTRON_PROVIDER_SUPPLIER, INSTALLED_PROVIDERS);

    static final Map<String, Version> KNOWN_NAMESPACES;

    private enum Version {

        VERSION_1_0("urn:elytron:1.0", null),
        VERSION_1_0_1("urn:elytron:1.0.1", VERSION_1_0),
        VERSION_1_1("urn:elytron:client:1.1", VERSION_1_0_1),
        VERSION_1_2("urn:elytron:client:1.2", VERSION_1_1),
        VERSION_1_3("urn:elytron:client:1.3", VERSION_1_2),
        VERSION_1_4("urn:elytron:client:1.4", VERSION_1_3),
        VERSION_1_5("urn:elytron:client:1.5", VERSION_1_4);

        final String namespace;

        /*
         * In the future we could support multiple parents but wait until that becomes a reality before adding it.
         */
        final Version parent;

        Version(String namespace, Version parent) {
            this.namespace = namespace;
            this.parent = parent;
        }


        boolean isAtLeast(Version version) {
            return this.equals(version) || (parent != null ? parent.isAtLeast(version) : false);
        }

    }

    static {
        Map<String, Version> knownNamespaces = new HashMap<>();
        for (Version version : Version.values()) {
            knownNamespaces.put(version.namespace, version);
        }
        KNOWN_NAMESPACES = Collections.unmodifiableMap(knownNamespaces);
    }

    private ElytronXmlParser() {
    }

    // authentication client document

    /**
     * Parse an Elytron authentication client configuration from a configuration discovered using the default wildfly-client-config discovery rules.
     *
     * @return the authentication context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static SecurityFactory<AuthenticationContext> parseAuthenticationClientConfiguration() throws ConfigXMLParseException {
        final ClientConfiguration clientConfiguration = ClientConfiguration.getInstance();
        if (clientConfiguration != null) try (final ConfigurationXMLStreamReader streamReader = clientConfiguration.readConfiguration(KNOWN_NAMESPACES.keySet())) {
            if (streamReader != null) {
                xmlLog.tracef("Parsing configuration from %s for namespace %s", streamReader.getUri(), streamReader.getNamespaceURI());
                return parseAuthenticationClientConfiguration(streamReader);
            } else {
                if (xmlLog.isTraceEnabled()) {
                    xmlLog.tracef("No configuration found for known namespaces '%s'", namespacesToString());
                }
            }
        }
        xmlLog.trace("Fallback to parse legacy configuration.");
        // Try legacy configuration next
        return parseLegacyConfiguration();
    }

    /**
     * Parse an Elytron authentication client configuration from a resource located at a specified {@link URI}.
     *
     * @param uri the {@link URI} of the configuration.
     * @return the authentication context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static SecurityFactory<AuthenticationContext> parseAuthenticationClientConfiguration(URI uri) throws ConfigXMLParseException {
        final ClientConfiguration clientConfiguration = ClientConfiguration.getInstance(uri);
        if (clientConfiguration != null) try (final ConfigurationXMLStreamReader streamReader = clientConfiguration.readConfiguration(KNOWN_NAMESPACES.keySet())) {
            if (streamReader != null) {
                xmlLog.tracef("Parsig configuration from %s for namespace %s", streamReader.getUri(), streamReader.getNamespaceURI());
                return parseAuthenticationClientConfiguration(streamReader);
            } else {
                if (xmlLog.isTraceEnabled()) {
                    xmlLog.tracef("No configuration found for known namespaces '%s'", namespacesToString());
                }
            }
        }
        xmlLog.trace("Fallback to parse legacy configuration.");
        // Try legacy configuration next
        return parseLegacyConfiguration();
    }

    private static String namespacesToString() {
        Iterator<String> namespaceIterator = KNOWN_NAMESPACES.keySet().iterator();
        StringBuilder namespaces = new StringBuilder(namespaceIterator.next());
        while (namespaceIterator.hasNext()) {
            namespaces.append(",").append(namespaceIterator.next());
        }

        return namespaces.toString();
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
                    Version xmlVersion = KNOWN_NAMESPACES.get(checkGetElementNamespace(reader));
                    switch (reader.getLocalName()) {
                        case "authentication-client": {
                            return parseAuthenticationClientType(reader, xmlVersion);
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
        xmlLog.trace("No authentication-client element found, falling back to empty AuthenticationContext");
        return AuthenticationContext::empty;
    }

    private static SecurityFactory<AuthenticationContext> parseLegacyConfiguration() {
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
                if (context != null) {
                    xmlLog.trace("Found AuthenticationContext in legacy configuration");
                    return context;
                }
            }
            xmlLog.trace("No legacy configuration available, using AuthenticationContext.empty()");
            return AuthenticationContext.empty();
        };
    }

    // authentication client types

    /**
     * Parse an XML element of type {@code authentication-client-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param xmlVersion the version of parsed XML
     * @return the authentication context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static SecurityFactory<AuthenticationContext> parseAuthenticationClientType(ConfigurationXMLStreamReader reader, final Version xmlVersion) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        ExceptionSupplier<RuleNode<AuthenticationConfiguration>, ConfigXMLParseException> authFactory = () -> null;
        ExceptionSupplier<RuleNode<SecurityFactory<SSLContext>>, ConfigXMLParseException> sslFactory = () -> null;
        Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap = new HashMap<>();
        Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap = new HashMap<>();
        Map<String, ExceptionSupplier<SecurityFactory<SSLContext>, ConfigXMLParseException>> sslContextsMap = new HashMap<>();
        Map<String, ExceptionSupplier<AuthenticationConfiguration, ConfigXMLParseException>> authenticationConfigurationsMap = new HashMap<>();
        final DeferredSupplier<Provider[]> providersSupplier = new DeferredSupplier<>(DEFAULT_PROVIDER_SUPPLIER);
        boolean netAuthenticator = false;
        int foundBits  = 0;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "authentication-rules": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        authFactory = parseRulesType(reader, xmlVersion, authenticationConfigurationsMap, (r, m) -> parseAuthenticationRuleType(r, xmlVersion, m));
                        break;
                    }
                    case "ssl-context-rules": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        sslFactory = parseRulesType(reader, xmlVersion, sslContextsMap, (r,m) -> parseSslContextRuleType(r, xmlVersion, m));
                        break;
                    }
                    case "authentication-configurations": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        parseAuthenticationConfigurationsType(reader, xmlVersion, authenticationConfigurationsMap, keyStoresMap, credentialStoresMap, providersSupplier);
                        break;
                    }
                    case "ssl-contexts": {
                        if (isSet(foundBits, 3)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 3);
                        parseSslContextsType(reader, xmlVersion, sslContextsMap, keyStoresMap, credentialStoresMap, providersSupplier);
                        break;
                    }
                    case "key-stores": {
                        if (isSet(foundBits, 4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 4);
                        parseKeyStoresType(reader, xmlVersion, keyStoresMap, credentialStoresMap, providersSupplier);
                        break;
                    }
                    case "net-authenticator": {
                        if (isSet(foundBits, 5)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 5);
                        netAuthenticator = true;
                        parseEmptyType(reader);
                        break;
                    }
                    case "credential-stores": {
                        if (isSet(foundBits, 6)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 6);
                        parseCredentialStoresType(reader, xmlVersion, keyStoresMap, credentialStoresMap, providersSupplier);
                        break;
                    }
                    case "providers": {
                        if (isSet(foundBits, 7)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 7);
                        Supplier<Provider[]> supplier = parseProvidersType(reader, xmlVersion);
                        if (supplier != null) {
                            providersSupplier.setSupplier(supplier);
                        }
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                assert reader.getLocalName().equals("authentication-client");
                if (netAuthenticator) {
                    Authenticator.setDefault(new ElytronAuthenticator());
                }
                // validate key and credential stores...
                for (ExceptionSupplier<KeyStore, ConfigXMLParseException> supplier : keyStoresMap.values()) {
                    supplier.get();
                }
                for (ExceptionSupplier<CredentialStore, ConfigXMLParseException> supplier : credentialStoresMap.values()) {
                    supplier.get();
                }
                final RuleNode<AuthenticationConfiguration> authNode = authFactory.get();
                final RuleNode<SecurityFactory<SSLContext>> sslNode = sslFactory.get();
                return () -> new AuthenticationContext(authNode, sslNode);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static void parseAuthenticationConfigurationsType(final ConfigurationXMLStreamReader reader, final Version xmlVersion, final Map<String, ExceptionSupplier<AuthenticationConfiguration, ConfigXMLParseException>> authenticationConfigurationsMap, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, final Supplier<Provider[]> providers) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "configuration": {
                        parseAuthenticationConfigurationType(reader, xmlVersion, authenticationConfigurationsMap, keyStoresMap, credentialStoresMap, providers);
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static void parseSslContextsType(final ConfigurationXMLStreamReader reader, final Version xmlVersion, final Map<String, ExceptionSupplier<SecurityFactory<SSLContext>, ConfigXMLParseException>> sslContextsMap, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, final Supplier<Provider[]> providers) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "ssl-context": {
                        parseSslContextType(reader, xmlVersion, sslContextsMap, keyStoresMap, credentialStoresMap, providers);
                        break;
                    }
                    case "default-ssl-context": {
                        final String name = parseNameType(reader);
                        sslContextsMap.put(name, () -> SSLContext::getDefault);
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static void parseSslContextType(final ConfigurationXMLStreamReader reader, final Version xmlVersion, final Map<String, ExceptionSupplier<SecurityFactory<SSLContext>, ConfigXMLParseException>> sslContextsMap, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, final Supplier<Provider[]> providers) throws ConfigXMLParseException {
        final String name = requireSingleAttribute(reader, "name");
        if (sslContextsMap.containsKey(name)) {
            throw xmlLog.xmlDuplicateSslContextName(name, reader);
        }
        final XMLLocation location = reader.getLocation();
        int foundBits = 0;
        String providerName = null;
        CipherSuiteSelector cipherSuiteSelector = null;
        ProtocolSelector protocolSelector = null;
        ExceptionSupplier<X509ExtendedKeyManager, ConfigXMLParseException> keyManagerSupplier = null;
        ExceptionSupplier<KeyStore, ConfigXMLParseException> trustStoreSupplier = null;
        DeferredSupplier<Provider[]> providersSupplier = new DeferredSupplier<>(providers);
        TrustManagerBuilder trustManagerBuilder = new TrustManagerBuilder(providersSupplier, location);

        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "key-store-ssl-certificate": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        keyManagerSupplier = parseKeyStoreSslCertificate(reader, xmlVersion, keyStoresMap, credentialStoresMap, providers);
                        break;
                    }
                    case "cipher-suite": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        cipherSuiteSelector = parseCipherSuiteSelectorType(reader, xmlVersion);
                        break;
                    }
                    case "protocol": {
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
                    case "providers": {
                        if (isSet(foundBits, 4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 4);
                        Supplier<Provider[]> supplier = parseProvidersType(reader, xmlVersion);
                        if (supplier != null) {
                            providersSupplier.setSupplier(supplier);
                        }
                        break;
                    }
                    case "trust-store": {
                        if (isSet(foundBits, 5)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 5);
                        trustStoreSupplier = parseTrustStoreRefType(reader, keyStoresMap);
                        break;
                    }
                    case "certificate-revocation-list": {
                        if (isSet(foundBits, 6)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 6);
                        parseCertificateRevocationList(reader, trustManagerBuilder, xmlVersion);
                        break;
                    }
                    case "trust-manager": {
                        if (isSet(foundBits, 7) || !xmlVersion.isAtLeast(Version.VERSION_1_1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 7);
                        parseTrustManager(reader, trustManagerBuilder, xmlVersion);
                        break;
                    }
                    case "ocsp": {
                        if (isSet(foundBits, 8) || !xmlVersion.isAtLeast(Version.VERSION_1_4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 8);
                        parseOcsp(reader, trustManagerBuilder, keyStoresMap);
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
                final ExceptionSupplier<X509ExtendedKeyManager, ConfigXMLParseException> finalKeyManagerSupplier = keyManagerSupplier;
                final ExceptionSupplier<KeyStore, ConfigXMLParseException> finalTrustStoreSupplier = trustStoreSupplier;
                final boolean initTrustManager = finalTrustStoreSupplier != null || isSet(foundBits, 7);
                sslContextsMap.putIfAbsent(name, () -> {
                    final SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
                    sslContextBuilder.setClientMode(true);
                    if (finalCipherSuiteSelector != null) {
                        sslContextBuilder.setCipherSuiteSelector(finalCipherSuiteSelector);
                    }
                    if (finalProtocolSelector != null) {
                        sslContextBuilder.setProtocolSelector(finalProtocolSelector);
                    }
                    if (finalKeyManagerSupplier != null) {
                        sslContextBuilder.setKeyManager(finalKeyManagerSupplier.get());
                    }
                    if (initTrustManager) {
                        if (finalTrustStoreSupplier != null) {
                            trustManagerBuilder.setTrustStore(finalTrustStoreSupplier.get());
                        }
                        try {
                            sslContextBuilder.setTrustManager(trustManagerBuilder.build());
                        } catch (GeneralSecurityException e) {
                            throw new ConfigXMLParseException(e);
                        }
                    }
                    sslContextBuilder.setProviderName(finalProviderName);
                    sslContextBuilder.setProviderSupplier(finalProvidersSupplier);
                    sslContextBuilder.setUseCipherSuitesOrder(true);
                    return sslContextBuilder.build();
                });
                return;
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static class TrustManagerBuilder {
        final Supplier<Provider[]> providers;
        final Location xmlLocation;
        String providerName = null;
        String algorithm = null;
        KeyStore trustStore;
        boolean crl = false;
        InputStream crlStream = null;
        int maxCertPath = 5;
        boolean ocsp = false;
        boolean preferCrls = false;
        boolean onlyLeafCert = false;
        boolean softFail = false;
        URI ocspResponder = null;
        boolean maxCertPathSet = false;
        String responderCertAlias = null;
        ExceptionSupplier<KeyStore, ConfigXMLParseException> responderStoreSupplier = null;

        TrustManagerBuilder(Supplier<Provider[]> providers, Location xmlLocation) {
            this.providers = providers;
            this.xmlLocation = xmlLocation;
        }

        void setProviderName(String providerName) {
            this.providerName = providerName;
        }

        void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        void setTrustStore(KeyStore trustStore) {
            this.trustStore = trustStore;
        }

        void setCrl() {
            this.crl = true;
        }

        void setCrlStream(InputStream crlStream) {
            this.crlStream = crlStream;
        }

        void setMaxCertPath(int maxCertPath) {
            checkMinimumParameter("maxCertPath", 1, maxCertPath);
            this.maxCertPath = maxCertPath;
            this.maxCertPathSet = true;
        }

        boolean isMaxCertPathSet() {
            return maxCertPathSet;
        }

        public void setOcsp() {
            this.ocsp = true;
        }

        public void setPreferCrls(boolean preferCrls) {
            this.preferCrls = preferCrls;
        }

        public void setOnlyLeafCert(boolean onlyLeafCert) {
            this.onlyLeafCert = onlyLeafCert;
        }

        public void setSoftFail(boolean softFail) {
            this.softFail = softFail;
        }

        public void setOcspResponder(URI ocspResponder) {
            this.ocspResponder = ocspResponder;
        }

        public void setOcspRescponderCertAlias(String alias) {
            this.responderCertAlias = alias;
        }

        public void setOcspResponderCertKeystoreSupplier(ExceptionSupplier<KeyStore, ConfigXMLParseException> supplier) {
            this.responderStoreSupplier = supplier;
        }

        X509TrustManager build() throws NoSuchAlgorithmException, KeyStoreException, ConfigXMLParseException {
            final String algorithm = this.algorithm != null ? this.algorithm : TrustManagerFactory.getDefaultAlgorithm();
            Provider provider = findProvider(providers, providerName, TrustManagerFactory.class, algorithm);
            if (provider == null) {
                throw xmlLog.xmlUnableToIdentifyProvider(xmlLocation, providerName, "TrustManagerFactory", algorithm);
            }

            final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm, provider);
            if (crl || ocsp) {
                X509RevocationTrustManager.Builder revocationBuilder = X509RevocationTrustManager.builder();
                revocationBuilder.setCrlStream(crlStream);
                revocationBuilder.setResponderURI(ocspResponder);
                revocationBuilder.setTrustManagerFactory(trustManagerFactory);
                revocationBuilder.setTrustStore(trustStore);
                revocationBuilder.setOnlyEndEntity(onlyLeafCert);
                revocationBuilder.setSoftFail(softFail);

                if (crl && ocsp) {
                    revocationBuilder.setPreferCrls(preferCrls);
                    revocationBuilder.setNoFallback(false);
                } else if (crl) {
                    revocationBuilder.setPreferCrls(true);
                    revocationBuilder.setNoFallback(true);
                } else {
                    revocationBuilder.setPreferCrls(false);
                    revocationBuilder.setNoFallback(true);
                }

                if (responderCertAlias != null) {
                    KeyStore responderStore = responderStoreSupplier != null ? responderStoreSupplier.get() : trustStore;
                    revocationBuilder.setOcspResponderCert((X509Certificate) responderStore.getCertificate(responderCertAlias));
                }

                return revocationBuilder.build();
            } else {
                trustManagerFactory.init(trustStore);
            }
            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager) {
                    return (X509TrustManager) trustManager;
                }
            }
            throw ElytronMessages.log.noDefaultTrustManager();
        }
    }

    private static class KeyManagerBuilder {
        final Supplier<Provider[]> providers;
        final Location xmlLocation;
        String providerName = null;
        String algorithm = null;
        ExceptionSupplier<KeyStore, ConfigXMLParseException> keyStoreSupplier;

        KeyManagerBuilder(Supplier<Provider[]> providers, Location xmlLocation) {
            this.providers = providers;
            this.xmlLocation = xmlLocation;
        }

        void setProviderName(String providerName) {
            this.providerName = providerName;
        }

        void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        void setKeyStoreSupplier(ExceptionSupplier<KeyStore, ConfigXMLParseException> keyStoreSupplier) {
            this.keyStoreSupplier = keyStoreSupplier;
        }

        X509ExtendedKeyManager build() throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, ConfigXMLParseException {
            final String algorithm = this.algorithm != null ? this.algorithm : KeyManagerFactory.getDefaultAlgorithm();
            Provider provider = findProvider(providers, providerName, KeyManagerFactory.class, algorithm);
            if (provider == null) {
                throw xmlLog.xmlUnableToIdentifyProvider(xmlLocation, providerName, "KeyManagerFactory", algorithm);
            }

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithm, provider);
            keyManagerFactory.init(keyStoreSupplier != null ? keyStoreSupplier.get() : null, null);

            for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
                if (keyManager instanceof X509ExtendedKeyManager) {
                    return (X509ExtendedKeyManager) keyManager;
                }
            }
            throw ElytronMessages.log.noDefaultKeyManager();
        }
    }

    private static void parseCertificateRevocationList(ConfigurationXMLStreamReader reader, TrustManagerBuilder builder, final Version xmlVersion) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String path = null;
        ExceptionSupplier<InputStream, IOException> resourceSource = null;
        URI uriSource = null;
        boolean gotSource = false;
        int maxCertPath = 0;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "path": {
                    if (gotSource) throw reader.unexpectedAttribute(i);
                    gotSource = true;
                    path = reader.getAttributeValueResolved(i);
                    break;
                }
                case "maximum-cert-path": { //Deprecated
                    if (builder.isMaxCertPathSet()) throw reader.unexpectedAttribute(i);
                    xmlLog.xmlDeprecatedElement("maximum-cert-path", reader.getLocation());
                    builder.setMaxCertPath(reader.getIntAttributeValueResolved(i, 1, Integer.MAX_VALUE));
                    break;
                }
                default: throw reader.unexpectedAttribute(i);
            }
        }
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "resource": {
                        if (gotSource || !xmlVersion.isAtLeast(Version.VERSION_1_1)) {
                            throw reader.unexpectedElement();
                        }
                        gotSource = true;
                        resourceSource = parseResourceType(reader, xmlVersion);
                        break;
                    }
                    case "uri": {
                        if (gotSource || !xmlVersion.isAtLeast(Version.VERSION_1_1)) {
                            throw reader.unexpectedElement();
                        }
                        gotSource = true;
                        uriSource = parseUriType(reader);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                builder.setCrl();
                if (gotSource) {
                    try {
                        if (path != null) builder.setCrlStream(new FileInputStream(path));
                        else if (resourceSource != null) builder.setCrlStream(resourceSource.get());
                        else if (uriSource != null) builder.setCrlStream(uriSource.toURL().openStream());
                    } catch (IOException e) {
                        throw new ConfigXMLParseException(e);
                    }
                }
                if (maxCertPath != 0) builder.setMaxCertPath(maxCertPath);
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static void parseOcsp(ConfigurationXMLStreamReader reader, TrustManagerBuilder builder, Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        boolean gotPreferCrls = false;
        boolean gotResponder = false;
        boolean gotResponderCertAlias = false;
        boolean gotResponderKeystore = false;
        builder.setOcsp();
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "responder": {
                    if (gotResponder) throw reader.unexpectedAttribute(i);
                    builder.setOcspResponder(reader.getURIAttributeValueResolved(i));
                    gotResponder = true;
                    break;
                }
                case "prefer-crls": {
                    if (gotPreferCrls) throw reader.unexpectedAttribute(i);
                    builder.setPreferCrls(reader.getBooleanAttributeValueResolved(i));
                    gotPreferCrls = true;
                    break;
                }
                case "responder-certificate": {
                    if (gotResponderCertAlias) throw reader.unexpectedAttribute(i);
                    builder.setOcspRescponderCertAlias(reader.getAttributeValueResolved(i));
                    gotResponderCertAlias = true;
                    break;
                }
                case "responder-keystore": {
                    if (gotResponderKeystore) throw reader.unexpectedAttribute(i);
                    builder.setOcspResponderCertKeystoreSupplier(keyStoresMap.get(reader.getAttributeValueResolved(i)));
                    gotResponderKeystore = true;
                    break;
                }
                default: throw reader.unexpectedAttribute(i);
            }
        }
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == END_ELEMENT) {
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static ExceptionSupplier<X509ExtendedKeyManager, ConfigXMLParseException> parseKeyStoreSslCertificate(ConfigurationXMLStreamReader reader,
            final Version xmlVersion, Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap,
            final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, final Supplier<Provider[]> providers)
            throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        final XMLLocation location = reader.getLocation();
        String providerName = null;
        String algorithm = null;
        String keyStoreName = null;
        String alias = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "provider-name": {
                    if (providerName != null || !xmlVersion.isAtLeast(Version.VERSION_1_2)) throw reader.unexpectedAttribute(i);
                    providerName = reader.getAttributeValueResolved(i);
                    break;
                }
                case "algorithm": {
                    if (providerName != null || !xmlVersion.isAtLeast(Version.VERSION_1_2)) throw reader.unexpectedAttribute(i);
                    if (algorithm != null) throw reader.unexpectedAttribute(i);
                    algorithm = reader.getAttributeValueResolved(i);
                    break;
                }
                case "key-store-name": {
                    if (keyStoreName != null) throw reader.unexpectedAttribute(i);
                    keyStoreName = reader.getAttributeValueResolved(i);
                    break;
                }
                case "alias": {
                    if (alias != null) throw reader.unexpectedAttribute(i);
                    alias = reader.getAttributeValueResolved(i);
                    break;
                }
                default: throw reader.unexpectedAttribute(i);
            }
        }
        if (keyStoreName == null) {
            throw missingAttribute(reader, "key-store-name");
        }
        ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> keyStoreCredential = null;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "key-store-credential": {
                        if (keyStoreCredential != null) throw reader.unexpectedElement();
                        keyStoreCredential = parseKeyStoreRefType(reader, xmlVersion, keyStoresMap, credentialStoresMap, providers);
                        break;
                    }
                    case "key-store-clear-password": {
                        if (keyStoreCredential != null) throw reader.unexpectedElement();
                        ExceptionSupplier<Password, ConfigXMLParseException> credential = parseClearPassword(reader, providers);
                        keyStoreCredential = () -> new PasswordEntry(credential.get());
                        break;
                    }
                    case "key-store-masked-password": {
                        if (keyStoreCredential != null || !xmlVersion.isAtLeast(Version.VERSION_1_4)) throw reader.unexpectedElement();
                        ExceptionSupplier<Password, ConfigXMLParseException> credential = parseMaskedPassword(reader, providers);
                        keyStoreCredential = () -> new PasswordEntry(credential.get());
                        break;
                    }
                    case "credential-store-reference": {
                        if (keyStoreCredential != null || !xmlVersion.isAtLeast(Version.VERSION_1_0_1)) {
                            throw reader.unexpectedElement();
                        }
                        final XMLLocation nestedLocation = reader.getLocation();
                        ExceptionSupplier<CredentialSource, ConfigXMLParseException> credentialSourceSupplier = parseCredentialStoreRefType(reader, credentialStoresMap);
                        keyStoreCredential = () -> {
                            try {
                                PasswordCredential passwordCredential = credentialSourceSupplier.get().getCredential(PasswordCredential.class);
                                if (passwordCredential == null) {
                                    throw new ConfigXMLParseException(xmlLog.couldNotObtainCredential(), reader);
                                }
                                return new PasswordEntry(passwordCredential.getPassword());
                            } catch (IOException e) {
                                throw xmlLog.xmlFailedToCreateCredential(nestedLocation, e);
                            }
                        };
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                final ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> finalKeyStoreCredential = keyStoreCredential;
                final String finalAlgorithm = algorithm;
                final String finalProviderName = providerName;
                final String finalKeyStoreName = keyStoreName;
                final String finalAlias = alias;
                return () -> {
                    try {
                        final ExceptionSupplier<KeyStore, ConfigXMLParseException> keyStoreSupplier = keyStoresMap.get(finalKeyStoreName);
                        if (keyStoreSupplier == null) {
                            throw xmlLog.xmlUnknownKeyStoreSpecified(location);
                        }
                        KeyStore keyStore = keyStoreSupplier.get();

                        if (xmlLog.isTraceEnabled()) {
                            xmlLog.tracef("Using KeyStore [%s] containing aliases %s", finalKeyStoreName, aliasesToString(keyStore.aliases()));
                        }

                        if (finalAlias != null) {
                            keyStore = FilteringKeyStore.filteringKeyStore(keyStore, AliasFilter.fromString(finalAlias));
                            if (xmlLog.isTraceEnabled()) xmlLog.tracef("Filtered aliases %s", aliasesToString(keyStore.aliases()));
                            if (keyStore.size() < 1) throw xmlLog.keyStoreEntryMissing(location, finalAlias);
                        }

                        String algorithmResolved = finalAlgorithm != null ? finalAlgorithm : KeyManagerFactory.getDefaultAlgorithm();
                        Provider provider = findProvider(providers, finalProviderName, KeyManagerFactory.class, algorithmResolved);
                        if (provider == null) {
                            throw xmlLog.xmlUnableToIdentifyProvider(location, finalProviderName, "KeyManagerFactory", algorithmResolved);
                        }

                        char[] password = keyStoreCredentialToPassword(finalKeyStoreCredential, providers);

                        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithmResolved, provider);
                        keyManagerFactory.init(keyStoreSupplier.get(), password);

                        for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
                            if (keyManager instanceof X509ExtendedKeyManager) {
                                return (X509ExtendedKeyManager) keyManager;
                            }
                        }
                        throw ElytronMessages.log.noDefaultKeyManager();
                    } catch (GeneralSecurityException | IOException e) {
                        throw xmlLog.xmlFailedToLoadKeyStoreData(location, e);
                    }
                };
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static String aliasesToString(Enumeration<String> aliases) {
        StringBuilder builder = new StringBuilder("[");
        while (aliases.hasMoreElements()) {
            builder.append(aliases.nextElement());
            if (aliases.hasMoreElements()) builder.append(", ");
        }
        return builder.append(']').toString();
    }

    private static void parseTrustManager(ConfigurationXMLStreamReader reader, TrustManagerBuilder builder, final Version xmlVersion) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String providerName = null;
        String algorithm = null;
        boolean gotSoftFail = false;
        boolean gotOnlyLeafCert = false;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "provider-name": {
                    if (providerName != null) throw reader.unexpectedAttribute(i);
                    providerName = reader.getAttributeValueResolved(i);
                    break;
                }
                case "algorithm": {
                    if (algorithm != null) throw reader.unexpectedAttribute(i);
                    algorithm = reader.getAttributeValueResolved(i);
                    break;
                }
                case "soft-fail": {
                    if (gotSoftFail || !xmlVersion.isAtLeast(Version.VERSION_1_4)) {
                        throw reader.unexpectedAttribute(i);
                    }
                    gotSoftFail = true;
                    builder.setSoftFail(reader.getBooleanAttributeValueResolved(i));
                    break;
                }
                case "maximum-cert-path": {
                    if (builder.isMaxCertPathSet() || !xmlVersion.isAtLeast(Version.VERSION_1_4)) {
                        throw reader.unexpectedAttribute(i);
                    }
                    builder.setMaxCertPath(reader.getIntAttributeValueResolved(i, 1, Integer.MAX_VALUE));
                    break;
                }
                case "only-leaf-cert": {
                    if (gotOnlyLeafCert || !xmlVersion.isAtLeast(Version.VERSION_1_4)) {
                        throw reader.unexpectedAttribute(i);
                    }
                    gotOnlyLeafCert = true;
                    builder.setOnlyLeafCert(reader.getBooleanAttributeValueResolved(i));
                    break;
                }
                default: throw reader.unexpectedAttribute(i);
            }
        }
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                builder.setProviderName(providerName);
                builder.setAlgorithm(algorithm);
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    static ExceptionUnaryOperator<RuleNode<SecurityFactory<SSLContext>>, ConfigXMLParseException> parseSslContextRuleType(final ConfigurationXMLStreamReader reader, final Version xmlVersion, final Map<String, ExceptionSupplier<SecurityFactory<SSLContext>, ConfigXMLParseException>> sslContextsMap) throws ConfigXMLParseException {
        final String attributeName = "use-ssl-context";
        final String name = requireSingleAttribute(reader, attributeName);
        final XMLLocation location = reader.getLocation();
        final MatchRule rule = parseAbstractMatchRuleType(reader, xmlVersion);
        return next -> {
            final ExceptionSupplier<SecurityFactory<SSLContext>, ConfigXMLParseException> factory = sslContextsMap.get(name);
            if (factory == null) throw xmlLog.xmlUnknownSslContextSpecified(location, name);
            return new RuleNode<>(next, rule, factory.get());
        };
    }

    static ExceptionUnaryOperator<RuleNode<AuthenticationConfiguration>, ConfigXMLParseException> parseAuthenticationRuleType(final ConfigurationXMLStreamReader reader, final Version xmlVersion, final Map<String, ExceptionSupplier<AuthenticationConfiguration, ConfigXMLParseException>> authenticationConfigurationsMap) throws ConfigXMLParseException {
        final String attributeName = "use-configuration";
        final String name = requireSingleAttribute(reader, attributeName);
        final XMLLocation location = reader.getLocation();
        final MatchRule rule = parseAbstractMatchRuleType(reader, xmlVersion);
        return next -> {
            final ExceptionSupplier<AuthenticationConfiguration, ConfigXMLParseException> factory = authenticationConfigurationsMap.get(name);
            if (factory == null) throw xmlLog.xmlUnknownAuthenticationConfigurationSpecified(location, name);
            return new RuleNode<>(next, rule, factory.get());
        };
    }

    static <C> ExceptionSupplier<RuleNode<C>, ConfigXMLParseException> parseRulesType(ConfigurationXMLStreamReader reader, final Version xmlVersion,
            final Map<String, ExceptionSupplier<C, ConfigXMLParseException>> configurations, ExceptionBiFunction<ConfigurationXMLStreamReader, Map<String, ExceptionSupplier<C, ConfigXMLParseException>>, ExceptionUnaryOperator<RuleNode<C>, ConfigXMLParseException>, ConfigXMLParseException> ruleParseFunction)
            throws ConfigXMLParseException {
        requireNoAttributes(reader);
        final List<ExceptionUnaryOperator<RuleNode<C>, ConfigXMLParseException>> rulesList = new ArrayList<>();
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "rule": {
                        rulesList.add(ruleParseFunction.apply(reader, configurations));
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return () -> {
                    RuleNode<C> node = null;
                    final ListIterator<ExceptionUnaryOperator<RuleNode<C>, ConfigXMLParseException>> iterator = rulesList.listIterator(rulesList.size());
                    // iterate backwards to build the singly-linked list in constant time
                    while (iterator.hasPrevious()) {
                        node = iterator.previous().apply(node);
                    }
                    return node;
                };
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    static void parseAuthenticationConfigurationType(ConfigurationXMLStreamReader reader, final Version xmlVersion, final Map<String, ExceptionSupplier<AuthenticationConfiguration, ConfigXMLParseException>> authenticationConfigurationsMap,
            final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap,
            final Supplier<Provider[]> providers) throws ConfigXMLParseException {
        final String name = requireSingleAttribute(reader, "name");
        if (authenticationConfigurationsMap.containsKey(name)) {
            throw xmlLog.xmlDuplicateAuthenticationConfigurationName(name, reader);
        }

        ExceptionUnaryOperator<AuthenticationConfiguration, ConfigXMLParseException> configuration = ignored -> AuthenticationConfiguration.empty();
        DeferredSupplier<Provider[]> providerSupplier = new DeferredSupplier<>(providers);
        configuration = andThenOp(configuration, parent -> parent.useProviders(providerSupplier));

        int foundBits = 0;
        if (! reader.hasNext()) {
            throw reader.unexpectedDocumentEnd();
        }
        while (reader.hasNext()) {
            int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    // -- set --
                    case "set-host": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        final String hostName = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useHost(hostName));
                        xmlLog.xmlDeprecatedElement(reader.getLocalName(), reader.getLocation());
                        break;
                    }
                    case "set-port": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        final int port = parsePortType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.usePort(port));
                        xmlLog.xmlDeprecatedElement(reader.getLocalName(), reader.getLocation());
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
                        final Map<String, String> mechanismProperties = parsePropertiesType(reader, xmlVersion);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useSaslMechanismProperties(mechanismProperties, true));
                        break;
                    }
                    case "sasl-mechanism-selector": {
                        if (isSet(foundBits, 6)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 6);
                        final SaslMechanismSelector selector = parseSaslMechanismSelectorType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.setSaslMechanismSelector(selector));
                        break;
                    }
                    case "credentials": {
                        if (isSet(foundBits, 9)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 9);
                        final ExceptionSupplier<CredentialSource, ConfigXMLParseException> credentialSource = parseCredentialsType(reader, xmlVersion, keyStoresMap, credentialStoresMap, providerSupplier);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useCredentials(credentialSource.get()));
                        break;
                    }
                    case "set-authorization-name": {
                        if (isSet(foundBits, 10)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 10);
                        final String authName = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useAuthorizationName(authName));
                        break;
                    }
                    case "providers": {
                        if (isSet(foundBits, 11)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 11);
                        Supplier<Provider[]> supplier = parseProvidersType(reader, xmlVersion);
                        if (supplier != null) {
                            providerSupplier.setSupplier(supplier);
                        }
                        break;
                    }
                    // these two are a <choice> which is why they share a bit #; you can have only one of them
                    case "use-provider-sasl-factory": {
                        if (isSet(foundBits, 12)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 12);
                        parseEmptyType(reader);
                        configuration = andThenOp(configuration, AuthenticationConfiguration::useSaslClientFactoryFromProviders);
                        break;
                    }
                    case "use-service-loader-sasl-factory": {
                        if (isSet(foundBits, 12)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 12);
                        final String moduleName = parseModuleRefType(reader);
                        final ClassLoader classLoader = (moduleName == null) ? ElytronXmlParser.class.getClassLoader() : ModuleLoader.getClassLoaderFromModule(reader, moduleName);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useSaslClientFactory(new ServiceLoaderSaslClientFactory(classLoader)));
                        break;
                    }
                    case "set-protocol": {
                        if (isSet(foundBits, 13)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 13);
                        final String protocol = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useProtocol(protocol));
                        xmlLog.xmlDeprecatedElement(reader.getLocalName(), reader.getLocation());
                        break;
                    }
                    case "webservices": {
                        if (isSet(foundBits, 14)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 14);
                        Map<String, ?> webServices = parseWebServicesType(reader, xmlVersion);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useWebServices(webServices));
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                final ExceptionUnaryOperator<AuthenticationConfiguration, ConfigXMLParseException> finalConfiguration = configuration;
                authenticationConfigurationsMap.put(name, () -> finalConfiguration.apply(AuthenticationConfiguration.empty()));
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    static Supplier<Provider[]> parseProvidersType(ConfigurationXMLStreamReader reader, final Version xmlVersion) throws ConfigXMLParseException {
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
                        providerSupplier = providerSupplier == null ? INSTALLED_PROVIDERS : ProviderUtil.aggregate(providerSupplier, INSTALLED_PROVIDERS);
                        break;
                    }
                    case "use-service-loader": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        final String moduleName = parseModuleRefType(reader);
                        Supplier<Provider[]> serviceLoaderSupplier = (moduleName == null) ?
                                ELYTRON_PROVIDER_SUPPLIER :
                                new ProviderServiceLoaderSupplier(ModuleLoader.getClassLoaderFromModule(reader, moduleName));
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

    static Map<String, ?> parseWebServicesType(ConfigurationXMLStreamReader reader, final Version xmlVersion) throws ConfigXMLParseException {
        requireNoAttributes(reader);

        int foundBits = 0;
        if (! reader.hasNext()) {
            throw reader.unexpectedDocumentEnd();
        }
        Map<String, String> propertiesMap = new HashMap<>();

        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "set-http-mechanism": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        final String httpMechName = parseNameType(reader);
                        propertiesMap.put("http-mechanism", httpMechName);
                        break;
                    }
                    case "set-ws-security-type": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        final String wsSecurityType = parseNameType(reader);
                        propertiesMap.put("ws-security-type", wsSecurityType);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return propertiesMap;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse the XML match-rule group.  On return, the reader will be positioned either at a start tag for an element
     * that is not included in this group, or at an end tag.
     *
     * @param reader the XML reader
     * @param xmlVersion the version of parsed XML
     * @return the parsed match rule
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static MatchRule parseAbstractMatchRuleType(ConfigurationXMLStreamReader reader, final Version xmlVersion) throws ConfigXMLParseException {
        MatchRule rule = MatchRule.ALL;
        int foundBits = 0;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    // -- match --
                    case "match-no-user": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        parseEmptyType(reader);
                        rule = rule.matchNoUser();
                        break;
                    }
                    case "match-user": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        rule = rule.matchUser(parseNameType(reader));
                        break;
                    }
                    case "match-protocol": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        rule = rule.matchProtocol(parseNameType(reader));
                        break;
                    }
                    case "match-host": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        rule = rule.matchHost(parseNameType(reader));
                        break;
                    }
                    case "match-path": {
                        if (isSet(foundBits, 3)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 3);
                        rule = rule.matchPath(parseNameType(reader));
                        break;
                    }
                    case "match-port": {
                        if (isSet(foundBits, 4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 4);
                        rule = rule.matchPort(parsePortType(reader));
                        break;
                    }
                    case "match-urn": {
                        if (isSet(foundBits, 5)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 5);
                        rule = rule.matchUrnName(parseNameType(reader));
                        break;
                    }
                    case "match-domain": {
                        if (isSet(foundBits, 6)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 6);
                        rule = rule.matchLocalSecurityDomain(parseNameType(reader));
                        break;
                    }
                    case "match-abstract-type": {
                        if (isSet(foundBits, 7)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 7);
                        rule = parseMatchAbstractType(rule, reader);
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
                case "name": name = reader.getAttributeValueResolved(i); break;
                case "authority": authority = reader.getAttributeValueResolved(i); break;
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

    private static <T, E extends Exception> ExceptionUnaryOperator<T, E> andThenOp(ExceptionUnaryOperator<T, E> first, ExceptionUnaryOperator<T, E> second) {
        return t -> second.apply(first.apply(t));
    }

    private static ExceptionSupplier<CredentialSource, ConfigXMLParseException> parseCredentialsType(final ConfigurationXMLStreamReader reader, final Version xmlVersion, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, Supplier<Provider[]> providers) throws ConfigXMLParseException {
        ExceptionUnaryOperator<CredentialSource, ConfigXMLParseException> function = parent -> CredentialSource.NONE;
        requireNoAttributes(reader);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "key-store-reference": {
                        final ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> supplier = parseKeyStoreRefType(reader, xmlVersion, keyStoresMap, credentialStoresMap, providers);
                        function = andThenOp(function, credentialSource -> credentialSource.with(new KeyStoreCredentialSource(new FixedSecurityFactory<KeyStore.Entry>(supplier.get()))));
                        break;
                    }
                    case "credential-store-reference": {
                        final ExceptionSupplier<CredentialSource, ConfigXMLParseException> supplier = parseCredentialStoreRefType(reader, credentialStoresMap);
                        function = andThenOp(function, credentialSource -> credentialSource.with(supplier.get()));
                        break;
                    }
                    case "clear-password": {
                        ExceptionSupplier<Password, ConfigXMLParseException> password = parseClearPassword(reader, providers);
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(new PasswordCredential(password.get()))));
                        break;
                    }
                    case "masked-password": {
                        if ( ! xmlVersion.isAtLeast(Version.VERSION_1_4)) {
                            throw reader.unexpectedElement();
                        }
                        final XMLLocation location = reader.getLocation();
                        ExceptionSupplier<Password, ConfigXMLParseException> password = parseMaskedPassword(reader, providers);
                        Password maskedPassword = password.get();
                        Password finalPassword;
                        try {
                            final PasswordFactory passwordFactory = PasswordFactory.getInstance(maskedPassword.getAlgorithm(), providers);
                            final ClearPasswordSpec spec = passwordFactory.getKeySpec(maskedPassword, ClearPasswordSpec.class);
                            final char[] clearPassword = spec.getEncodedPassword();
                            PasswordFactory clearPasswordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, providers);
                            finalPassword = clearPasswordFactory.generatePassword(new ClearPasswordSpec(clearPassword)).castAs(ClearPassword.class);
                        } catch (InvalidKeySpecException | NoSuchAlgorithmException cause) {
                            throw xmlLog.xmlFailedToCreateCredential(location, cause);
                        }
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(new PasswordCredential(finalPassword))));
                        break;
                    }
                    case "key-pair": {
                        KeyPair keyPair = parseKeyPair(reader, xmlVersion);
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(new KeyPairCredential(keyPair))));
                        break;
                    }
                    case "certificate": {
                        X509CertificateChainPrivateCredential credential = parseCertificateType(reader, xmlVersion);
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(credential)));
                        break;
                    }
                    case "public-key-pem": {
                        PublicKey publicKey = parsePem(reader, PublicKey.class);
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(new PublicKeyCredential(publicKey))));
                        break;
                    }
                    case "bearer-token": {
                        BearerTokenCredential bearerToken = parseBearerTokenType(reader);
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(bearerToken)));
                        break;
                    }
                    case "oauth2-bearer-token": {
                        final ExceptionSupplier<CredentialSource, ConfigXMLParseException> oauthCredentialSourceSupplier = parseOAuth2BearerTokenType(reader, credentialStoresMap, xmlVersion);
                        function = andThenOp(function, credentialSource -> credentialSource.with(oauthCredentialSourceSupplier.get()));
                        break;
                    }
                    case "local-kerberos": {
                        if ( ! xmlVersion.isAtLeast(Version.VERSION_1_1)) {
                            throw reader.unexpectedElement();
                        }
                        CredentialSource kerberosCredentialSource = parseLocalKerberos(reader);
                        function = andThenOp(function, credentialSource -> credentialSource.with(kerberosCredentialSource));
                        xmlLog.xmlDeprecatedElement(reader.getLocalName(), reader.getLocation());
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

    private static KeyPair parseKeyPair(final ConfigurationXMLStreamReader reader, final Version xmlVersion) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "private-key-pem": {
                        if (privateKey != null) throw reader.unexpectedElement();
                        privateKey = parsePem(reader, PrivateKey.class);
                        break;
                    }
                    case "public-key-pem": {
                        if (publicKey != null) throw reader.unexpectedElement();
                        publicKey = parsePem(reader, PublicKey.class);
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                if (privateKey == null) throw reader.missingRequiredElement(xmlVersion.namespace, "private-key-pem");
                if (publicKey == null) throw reader.missingRequiredElement(xmlVersion.namespace, "public-key-pem");
                return new KeyPair(publicKey, privateKey);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static X509CertificateChainPrivateCredential parseCertificateType(final ConfigurationXMLStreamReader reader, final Version xmlVersion) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        PrivateKey privateKey = null;
        X509Certificate[] certificates = null;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "private-key-pem": {
                        if (privateKey != null) throw reader.unexpectedElement();
                        privateKey = parsePem(reader, PrivateKey.class);
                        break;
                    }
                    case "pem": {
                        if (certificates != null) throw reader.unexpectedElement();
                        certificates = parseMultiPem(reader, X509Certificate.class, X509Certificate[]::new);
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                if (privateKey == null) throw reader.missingRequiredElement(xmlVersion.namespace, "private-key-pem");
                if (certificates == null) throw reader.missingRequiredElement(xmlVersion.namespace, "pem");
                return new X509CertificateChainPrivateCredential(privateKey, certificates);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static <P> P[] parseMultiPem(final ConfigurationXMLStreamReader reader, final Class<P> pemType, final IntFunction<P[]> ctor) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        final Iterator<PemEntry<?>> pemContent = Pem.parsePemContent(CodePointIterator.ofString(reader.getElementText()));
        if (! reader.hasNext()) throw reader.unexpectedDocumentEnd();
        final ArrayList<P> arrayList = new ArrayList<>();
        while (pemContent.hasNext()) {
            final PemEntry<?> pemEntry = pemContent.next();
            final P pem = pemEntry.tryCast(pemType);
            if (pem == null) throw xmlLog.xmlWrongPemType(reader, pemType, pemEntry.getEntry().getClass());
            arrayList.add(pem);
        }
        if (arrayList.isEmpty()) throw xmlLog.xmlNoPemContent(reader);
        return arrayList.toArray(ctor.apply(arrayList.size()));
    }

    private static <P> P parsePem(final ConfigurationXMLStreamReader reader, final Class<P> pemType) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        final Iterator<PemEntry<?>> pemContent = Pem.parsePemContent(CodePointIterator.ofString(reader.getElementText()));
        if (! reader.hasNext()) throw reader.unexpectedDocumentEnd();
        if (! pemContent.hasNext()) throw xmlLog.xmlNoPemContent(reader);
        final PemEntry<?> pemEntry = pemContent.next();
        final P pem = pemEntry.tryCast(pemType);
        if (pem == null) throw xmlLog.xmlWrongPemType(reader, pemType, pemEntry.getEntry().getClass());
        return pem;
    }

    /**
     * Parse an XML element of type {@code key-stores-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param xmlVersion the version of parsed XML
     * @param keyStoresMap the map of key stores to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static void parseKeyStoresType(ConfigurationXMLStreamReader reader, final Version xmlVersion, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, final Supplier<Provider[]> providers) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "key-store": {
                        parseKeyStoreType(reader, xmlVersion, keyStoresMap, credentialStoresMap, providers);
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
     * @param xmlVersion the version of parsed XML
     * @param keyStoresMap the map of key stores to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static void parseKeyStoreType(ConfigurationXMLStreamReader reader, final Version xmlVersion, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap,
            final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, final Supplier<Provider[]> providers) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String type = null;
        String provider = null;
        Boolean wrap = null;
        DeferredSupplier<Provider[]> providersSupplier = new DeferredSupplier<>(providers);
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
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
                case "wrap-passwords": {
                    if (wrap != null) throw reader.unexpectedAttribute(i);
                    wrap = Boolean.valueOf(Boolean.parseBoolean(reader.getAttributeValueResolved(i)));
                    break;
                }
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        if (type == null && !xmlVersion.isAtLeast(Version.VERSION_1_3)) {
            throw missingAttribute(reader, "type");
        }
        if (name == null) {
            throw missingAttribute(reader, "name");
        }
        final XMLLocation location = reader.getLocation();
        ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory = null;
        boolean gotSource = false;
        boolean gotCredential = false;
        boolean gotProviders = false;

        String fileSource = null;
        ExceptionSupplier<InputStream, IOException> resourceSource = null;
        URI uriSource = null;

        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "key-store-credential": {
                        // group 2
                        if (gotCredential) {
                            throw reader.unexpectedElement();
                        }
                        gotCredential = true;
                        final XMLLocation nestedLocation = reader.getLocation();
                        final ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> entryFactory = parseKeyStoreRefType(reader, xmlVersion, keyStoresMap, credentialStoresMap, providersSupplier);
                        passwordFactory = () -> {
                            final KeyStore.Entry entry = entryFactory.get();
                            if (entry instanceof PasswordEntry) try {
                                final Password password = ((PasswordEntry) entry).getPassword();
                                final PasswordFactory passwordFactory1 = PasswordFactory.getInstance(password.getAlgorithm(), providersSupplier);
                                final ClearPasswordSpec passwordSpec = passwordFactory1.getKeySpec(password, ClearPasswordSpec.class);
                                return passwordSpec.getEncodedPassword();
                            } catch (GeneralSecurityException e) {
                                throw xmlLog.xmlFailedToCreateCredential(nestedLocation, e);
                            }
                            return null;
                        };
                        break;
                    }
                    case "credential-store-reference": {
                        if (gotCredential || !xmlVersion.isAtLeast(Version.VERSION_1_0_1)) {
                            throw reader.unexpectedElement();
                        }
                        gotCredential = true;
                        final XMLLocation nestedLocation = reader.getLocation();
                        ExceptionSupplier<CredentialSource, ConfigXMLParseException> credentialSourceSupplier = parseCredentialStoreRefType(reader, credentialStoresMap);
                        passwordFactory = () -> {
                            try {
                                return credentialSourceSupplier.get().applyToCredential(PasswordCredential.class,
                                        c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
                            } catch (IOException e) {
                                throw xmlLog.xmlFailedToCreateCredential(nestedLocation, e);
                            }
                        };
                        break;
                    }
                    case "key-store-clear-password": {
                        // group 2
                        if (gotCredential) {
                            throw reader.unexpectedElement();
                        }
                        gotCredential = true;
                        final ExceptionSupplier<Password, ConfigXMLParseException> clearPassword = parseClearPassword(reader, providersSupplier);
                        passwordFactory = () -> ((ClearPassword)clearPassword.get()).getPassword();
                        break;
                    }
                    case "key-store-masked-password": {
                        // group 2
                        if (gotCredential || !xmlVersion.isAtLeast(Version.VERSION_1_4)) {
                            throw reader.unexpectedElement();
                        }
                        gotCredential = true;
                        final XMLLocation nestedLocation = reader.getLocation();
                        final ExceptionSupplier<Password, ConfigXMLParseException> maskedPassword = parseMaskedPassword(reader, providersSupplier);
                        passwordFactory = () -> {
                            try {
                                Password password = maskedPassword.get();
                                PasswordFactory factory = PasswordFactory.getInstance(password.getAlgorithm());
                                ClearPasswordSpec spec = factory.getKeySpec(password, ClearPasswordSpec.class);
                                return spec.getEncodedPassword();
                            } catch (GeneralSecurityException e) {
                                throw xmlLog.xmlFailedToCreateCredential(nestedLocation, e);
                            }
                        };
                        break;
                    }
                    case "file": {
                        // group 1
                        if (gotSource || gotCredential) {
                            throw reader.unexpectedElement();
                        }
                        gotSource = true;
                        fileSource = parseNameType(reader);
                        break;
                    }
                    case "resource": {
                        // group 1
                        if (gotSource || gotCredential) {
                            throw reader.unexpectedElement();
                        }
                        gotSource = true;
                        resourceSource = parseResourceType(reader, xmlVersion);
                        break;
                    }
                    case "uri": {
                        // group 1
                        if (gotSource || gotCredential) {
                            throw reader.unexpectedElement();
                        }
                        gotSource = true;
                        uriSource = parseUriType(reader);
                        break;
                    }
                    case "providers": {
                        if (gotProviders || !xmlVersion.isAtLeast(Version.VERSION_1_1)) {
                            throw reader.unexpectedElement();
                        }
                        gotProviders = true;
                        Supplier<Provider[]> supplier = parseProvidersType(reader, xmlVersion);
                        if (supplier != null) {
                            providersSupplier.setSupplier(supplier);
                        }
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                ExceptionSupplier<KeyStore, ConfigXMLParseException> keyStoreFactory = null;
                if (type == null || type.equalsIgnoreCase("automatic")) {
                    keyStoreFactory = new UnknownTypeFileKeyStoreFactory(providers, provider, passwordFactory, fileSource, resourceSource, uriSource, location);
                    if (wrap) {
                        keyStoreFactory = new PasswordKeyStoreFactory(keyStoreFactory);
                    }
                } else {
                    keyStoreFactory = new KeyStoreCreateFactory(providersSupplier, provider, type, location);
                    if (wrap == Boolean.TRUE) {
                        keyStoreFactory = new PasswordKeyStoreFactory(keyStoreFactory);
                    }
                    if (fileSource != null) {
                        keyStoreFactory = new FileLoadingKeyStoreFactory(keyStoreFactory, passwordFactory, fileSource, location);
                    } else if (resourceSource != null) {
                        keyStoreFactory = new ResourceLoadingKeyStoreFactory(keyStoreFactory, passwordFactory, resourceSource, location);
                    } else if (uriSource != null) {
                        keyStoreFactory = new URILoadingKeyStoreFactory(keyStoreFactory, passwordFactory, uriSource, location);
                    } else {
                        keyStoreFactory = new NullLoadingKeyStoreFactory(keyStoreFactory, passwordFactory, location);
                    }
                }
                keyStoresMap.put(name, keyStoreFactory);
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code key-store-ref-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param xmlVersion the version of parsed XML
     * @param keyStoresMap the map of key stores to use
     * @param credentialStoresMap the map of credential stores to use
     * @param providers supplier of providers for loading services
     * @return the key store entry factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> parseKeyStoreRefType(ConfigurationXMLStreamReader reader, final Version xmlVersion,
            final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap,
            final Supplier<Provider[]> providers) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        final XMLLocation location = reader.getLocation();
        String keyStoreName = null;
        String alias = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "key-store-name": {
                    if (keyStoreName != null) throw reader.unexpectedAttribute(i);
                    keyStoreName = reader.getAttributeValueResolved(i);
                    break;
                }
                case "alias": {
                    if (alias != null) throw reader.unexpectedAttribute(i);
                    alias = reader.getAttributeValueResolved(i);
                    break;
                }
                default: throw reader.unexpectedElement();
            }
        }
        if (keyStoreName == null) {
            throw missingAttribute(reader, "key-store-name");
        }
        ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> keyStoreCredential = null;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "key-store-credential": {
                        if (keyStoreCredential != null) throw reader.unexpectedElement();
                        keyStoreCredential = parseKeyStoreRefType(reader, xmlVersion, keyStoresMap, credentialStoresMap, providers);
                        break;
                    }
                    case "key-store-clear-password": {
                        if (keyStoreCredential != null) throw reader.unexpectedElement();
                        ExceptionSupplier<Password, ConfigXMLParseException> credential = parseClearPassword(reader, providers);
                        keyStoreCredential = () -> new PasswordEntry(credential.get());
                        break;
                    }
                    case "key-store-masked-password": {
                        if (keyStoreCredential != null || !xmlVersion.isAtLeast(Version.VERSION_1_4)) throw reader.unexpectedElement();
                        ExceptionSupplier<Password, ConfigXMLParseException> credential = parseMaskedPassword(reader, providers);
                        keyStoreCredential = () -> new PasswordEntry(credential.get());
                        break;
                    }
                    case "credential-store-reference": {
                        if (keyStoreCredential != null || !xmlVersion.isAtLeast(Version.VERSION_1_0_1)) {
                            throw reader.unexpectedElement();
                        }
                        final XMLLocation nestedLocation = reader.getLocation();
                        ExceptionSupplier<CredentialSource, ConfigXMLParseException> credentialSourceSupplier = parseCredentialStoreRefType(reader, credentialStoresMap);
                        keyStoreCredential = () -> {
                            try {
                                PasswordCredential passwordCredential = credentialSourceSupplier.get().getCredential(PasswordCredential.class);
                                if (passwordCredential == null) {
                                    throw new ConfigXMLParseException(xmlLog.couldNotObtainCredential(), reader);
                                }
                                return new PasswordEntry(passwordCredential.getPassword());
                            } catch (IOException e) {
                                throw xmlLog.xmlFailedToCreateCredential(nestedLocation, e);
                            }
                        };
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                final ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> finalKeyStoreCredential = keyStoreCredential;
                final String finalKeyStoreName = keyStoreName;
                final String finalAlias = alias;
                return () -> {
                    try {
                        final ExceptionSupplier<KeyStore, ConfigXMLParseException> keyStoreSupplier = keyStoresMap.get(finalKeyStoreName);
                        if (keyStoreSupplier == null) {
                            throw xmlLog.xmlUnknownKeyStoreSpecified(location);
                        }
                        char[] password = keyStoreCredentialToPassword(finalKeyStoreCredential, providers);
                        final KeyStore.ProtectionParameter protectionParameter = password != null ? new KeyStore.PasswordProtection(password) : null;
                        if (finalAlias != null) {
                            KeyStore.Entry finalEntry = keyStoreSupplier.get().getEntry(finalAlias, protectionParameter == null ? null : protectionParameter);
                            if (finalEntry == null) {
                                throw xmlLog.keyStoreEntryMissing(location, finalAlias);
                            }
                            return finalEntry;
                        } else {
                            //  allow to retrieve entry without providing alias only if keystore includes one and only entry.
                            if (keyStoreSupplier.get().size() > 1) {
                                throw xmlLog.missingAlias(location);
                            } else if (keyStoreSupplier.get().aliases().hasMoreElements()) {
                                String firstAlias = keyStoreSupplier.get().aliases().nextElement();
                                KeyStore.Entry finalEntry = keyStoreSupplier.get().getEntry(firstAlias, protectionParameter == null ? null : protectionParameter);
                                if (finalEntry == null) {
                                    throw xmlLog.keyStoreEntryMissing(location, firstAlias);
                                }
                                return finalEntry;
                            } else {
                                return null;
                            }
                        }
                    } catch (GeneralSecurityException e) {
                        throw xmlLog.xmlFailedToLoadKeyStoreData(location, e);
                    }
                };
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static char[] keyStoreCredentialToPassword(ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> keyStoreCredential,
            Supplier<Provider[]> providers) throws GeneralSecurityException, ConfigXMLParseException {
        final KeyStore.Entry entry = keyStoreCredential == null ? null : keyStoreCredential.get();
        if (entry instanceof PasswordEntry) {
            Password password = ((PasswordEntry) entry).getPassword();
            final PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm(), providers);
            password = passwordFactory.translate(password);
            final ClearPasswordSpec spec = passwordFactory.getKeySpec(password, ClearPasswordSpec.class);
            return spec.getEncodedPassword();
        } else if (entry instanceof KeyStore.SecretKeyEntry) {
            final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            final SecretKeyFactory instance = SecretKeyFactory.getInstance(secretKey.getAlgorithm());
            final SecretKeySpec keySpec = (SecretKeySpec) instance.getKeySpec(secretKey, SecretKeySpec.class);
            final byte[] encoded = keySpec.getEncoded();
            return encoded == null ? null : new String(encoded, StandardCharsets.UTF_8).toCharArray();
        } else {
            return null;
        }
    }

    /**
     * Parse an XML element of type {@code trust-store-ref-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param keyStoresMap the map of key stores to use
     * @return the key store entry factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionSupplier<KeyStore, ConfigXMLParseException> parseTrustStoreRefType(ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        final XMLLocation location = reader.getLocation();
        String keyStoreName = null;
        String alias = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "key-store-name": {
                    if (keyStoreName != null) throw reader.unexpectedAttribute(i);
                    keyStoreName = reader.getAttributeValueResolved(i);
                    break;
                }
                default: throw reader.unexpectedElement();
            }
        }
        if (keyStoreName == null) {
            throw missingAttribute(reader, "key-store-name");
        }
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                final ExceptionSupplier<KeyStore, ConfigXMLParseException> keyStoreSupplier = keyStoresMap.get(keyStoreName);
                if (keyStoreSupplier == null) {
                    throw xmlLog.xmlUnknownKeyStoreSpecified(location);
                }
                return keyStoreSupplier;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    static ExceptionSupplier<CredentialSource, ConfigXMLParseException> parseCredentialStoreRefType(ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String storeName = null;
        String alias = null;
        String clearText = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "store": {
                    if (storeName != null) throw reader.unexpectedAttribute(i);
                    storeName = reader.getAttributeValueResolved(i);
                    break;
                }
                case "alias": {
                    if (alias != null) throw reader.unexpectedAttribute(i);
                    alias = reader.getAttributeValueResolved(i);
                    break;
                }
                case "clear-text": {
                    if (clearText != null) throw reader.unexpectedAttribute(i);
                    clearText = reader.getAttributeValueResolved(i);
                    break;
                }
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        if (! reader.hasNext()) throw reader.unexpectedDocumentEnd();
        if (reader.nextTag() != END_ELEMENT) throw reader.unexpectedContent();
        final XMLLocation finalLocation = reader.getLocation();
        final String finalStoreName = storeName;
        final String finalClearText = clearText;
        final String finalAlias = alias;
        if (finalStoreName == null && finalClearText == null) throw xmlLog.xmlInvalidCredentialStoreRef(reader.getLocation());
        if (finalStoreName != null && finalAlias == null) throw missingAttribute(reader, "alias");
        return () -> {
            if (finalStoreName != null) {
                final ExceptionSupplier<CredentialStore, ConfigXMLParseException> supplier = credentialStoresMap.get(finalStoreName);
                if (supplier == null) {
                    throw xmlLog.xmlCredentialStoreNameNotDefined(finalLocation, finalStoreName);
                }
                final CredentialStore credentialStore = supplier.get();
                return new CredentialStoreCredentialSource(credentialStore, finalAlias);
            } else {
                final PasswordCredential passwordCredential = new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, finalClearText.toCharArray()));
                return IdentityCredentials.NONE.withCredential(passwordCredential);
            }
        };
    }

    /**
     * Parse an XML element of type {@code credential-stores-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param xmlVersion the version of parsed XML
     * @param keyStoresMap the key stores map
     * @param credentialStoresMap the map of  credential stores to use  @throws ConfigXMLParseException if the resource failed to be parsed
     */
    private static void parseCredentialStoresType(ConfigurationXMLStreamReader reader, final Version xmlVersion, Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, final Supplier<Provider[]> providers) throws ConfigXMLParseException {
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
                        parseCredentialStoreType(reader, xmlVersion, keyStoresMap, credentialStoresMap, providers);
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
     * @param keyStoresMap the key stores map
     * @param credentialStoresMap the map of  credential stores to fill  @throws ConfigXMLParseException if the resource failed to be parsed
     */
    private static void parseCredentialStoreType(ConfigurationXMLStreamReader reader, final Version xmlVersion, Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, final Supplier<Provider[]> providers) throws ConfigXMLParseException {
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
                        credentialSourceSupplier = parseCredentialsType(reader, xmlVersion, keyStoresMap, credentialStoresMap, providersSupplier);
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
    private static void parseAttributesType(ConfigurationXMLStreamReader reader, final Version xmlVersion, final Map<String, String> attributesMap) throws ConfigXMLParseException {
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

    /**
     * Parse an XML element of type {@code resource-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param xmlVersion the version of the XML being parsed
     * @return An {@code ExceptionSupplier<InputStream, IOException>} for the referenced resource
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionSupplier<InputStream, IOException> parseResourceType(ConfigurationXMLStreamReader reader, Version xmlVersion) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String module = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("name")) {
                name = reader.getAttributeValueResolved(i);
            } else if (reader.getAttributeLocalName(i).equals("module-name") && xmlVersion.isAtLeast(Version.VERSION_1_1)) {
                module = reader.getAttributeValueResolved(i);
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
                final String resourceName = name;
                final ClassLoader classLoader = module != null ? ModuleLoader.getClassLoaderFromModule(reader, module) : Thread.currentThread().getContextClassLoader();
                return () -> {
                    ClassLoader actualClassLoader = classLoader != null ? classLoader : ElytronXmlParser.class.getClassLoader();
                    final InputStream stream = actualClassLoader.getResourceAsStream(resourceName);
                    if (stream == null) throw new FileNotFoundException(resourceName);
                    return stream;
                };
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
                String s = reader.getAttributeValueResolved(i);
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
                pattern = Pattern.compile(reader.getAttributeValueResolved(i));
            } else if (reader.getAttributeLocalName(i).equals("replacement")) {
                replacement = reader.getAttributeValueResolved(i);
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
                String s = reader.getAttributeValueResolved(i);
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
                uri = reader.getURIAttributeValueResolved(i);
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

    static SaslMechanismSelector parseSaslMechanismSelectorType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        SaslMechanismSelector selector = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("selector")) {
                selector = SaslMechanismSelector.fromString(reader.getAttributeValueResolved(i));
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
     * Parse an XML element of type {@code ssl-cipher-selector-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the parsed cipher suite selector
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static CipherSuiteSelector parseCipherSuiteSelectorType(ConfigurationXMLStreamReader reader, Version xmlVersion) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        CipherSuiteSelector selector = null;
        CipherSuiteSelector names = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("selector")) {
                selector = CipherSuiteSelector.fromString(reader.getAttributeValueResolved(i));
            } else if (xmlVersion.isAtLeast(Version.VERSION_1_5) && reader.getAttributeLocalName(i).equals("names")) {
                names = CipherSuiteSelector.fromNamesString(reader.getAttributeValueResolved(i));
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (selector == null && ! xmlVersion.isAtLeast(Version.VERSION_1_5)) {
            throw missingAttribute(reader, "selector");
        } else if (selector == null && names == null && xmlVersion.isAtLeast(Version.VERSION_1_5)) {
            throw xmlLog.atLeastOneCipherSuiteAttributeMustBeProvided("selector", "names");
        }
        if (selector == null) {
            selector = CipherSuiteSelector.openSslDefault(); // default cipher suites pre TLSv1.3
        }
        if ((names == null) && xmlVersion.isAtLeast(Version.VERSION_1_5)) {
            names = CipherSuiteSelector.openSslDefaultCipherSuites(); // default cipher suites for TLSv1.3
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return CipherSuiteSelector.aggregate(names, selector);
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
     * @return the corresponding module name
     * @throws ConfigXMLParseException if the resource failed to be parsed or the module is not found
     */
    static String parseModuleRefType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String moduleName = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("module-name")) {
                moduleName = reader.getAttributeValueResolved(i);
            } else {
                throw reader.unexpectedAttribute(i);
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

    /**
     * Parse an XML element of type {@code masked-password-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return a {@link MaskedPassword} supplier
     * @throws ConfigXMLParseException if the resource failed to be parsed or the module is not found
     */
    static ExceptionSupplier<Password, ConfigXMLParseException> parseMaskedPassword(ConfigurationXMLStreamReader reader, Supplier<Provider[]> providers) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String algorithm = MaskedPassword.ALGORITHM_MASKED_MD5_DES;
        char[] initialKeyMaterial = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();
        int iterationCount = 0;
        byte[] salt = null;
        byte[] maskedPasswordBytes = null;
        byte[] initializationVector = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "algorithm":
                    algorithm = reader.getAttributeValueResolved(i);
                    break;
                case "key-material":
                    initialKeyMaterial = reader.getAttributeValueResolved(i).toCharArray();
                    break;
                case "iteration-count":
                    iterationCount = reader.getIntAttributeValueResolved(i, 1, Integer.MAX_VALUE);
                    break;
                case "salt":
                    salt = CodePointIterator.ofString(reader.getAttributeValueResolved(i)).asUtf8().drain();
                    break;
                case "masked-password":
                    maskedPasswordBytes = CodePointIterator.ofString(reader.getAttributeValueResolved(i)).base64Decode().drain();
                    break;
                case "initialization-vector":
                    initializationVector = CodePointIterator.ofString(reader.getAttributeValueResolved(i)).base64Decode().drain();
                    break;
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        if (iterationCount == 0) throw missingAttribute(reader, "iteration-count");
        if (salt == null) throw missingAttribute(reader, "salt");
        if (maskedPasswordBytes == null) throw missingAttribute(reader, "masked-password");
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                final XMLLocation location = reader.getLocation();
                if (!MaskedPassword.isMaskedAlgorithm(algorithm)) {
                    throw xmlLog.xmlUnsupportedAlgorithmForType(location, algorithm, MaskedPassword.class.getSimpleName());
                }
                final String finalAlgorithm = algorithm;
                final MaskedPasswordSpec spec = new MaskedPasswordSpec(initialKeyMaterial, iterationCount, salt, maskedPasswordBytes, initializationVector);
                return () -> {
                    try {
                        PasswordFactory factory = PasswordFactory.getInstance(finalAlgorithm, providers);
                        return Assert.assertNotNull(factory.generatePassword(spec).castAs(MaskedPassword.class));
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




    static Map<String, String> parsePropertiesType(ConfigurationXMLStreamReader reader, final Version xmlVersion) throws ConfigXMLParseException {
        if (reader.getAttributeCount() > 0) {
            throw reader.unexpectedAttribute(0);
        }

        Map<String, String> propertiesMap = new HashMap<>();

        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
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
                                    key = reader.getAttributeValueResolved(i);
                                    break;
                                case "value":
                                    if (value != null)
                                        throw reader.unexpectedAttribute(i);
                                    value = reader.getAttributeValueResolved(i);
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

    /**
     * Parse an XML element of type {@code bearer-token-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static BearerTokenCredential parseBearerTokenType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        String value = requireSingleAttribute(reader, "value");
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return new BearerTokenCredential(value);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code oauth2-bearer-token-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param xmlVersion the version of parsed XML
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionSupplier<CredentialSource, ConfigXMLParseException> parseOAuth2BearerTokenType(ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, final Version xmlVersion) throws ConfigXMLParseException {
        URI tokenEndpointUri = requireSingleURIAttribute(reader, "token-endpoint-uri");
        ExceptionSupplier<OAuth2CredentialSource.Builder, ConfigXMLParseException> builderSupplier = null;
        DeferredSupplier<Provider[]> providersSupplier = new DeferredSupplier<>(ProviderFactory.getElytronProviderSupplier(WildFlyElytronPasswordProvider.class.getClassLoader()));
        builderSupplier = () -> {
            try {
                return OAuth2CredentialSource.builder(tokenEndpointUri.toURL());
            } catch (MalformedURLException e) {
                throw xmlLog.xmlInvalidUrl(tokenEndpointUri.toString());
            }
        };
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                switch (reader.getLocalName()) {
                    case "resource-owner-credentials": {
                        builderSupplier = parseOAuth2ResourceOwnerCredentials(reader, builderSupplier, credentialStoresMap, xmlVersion);
                        break;
                    }
                    case "client-credentials": {
                        builderSupplier = parseOAuth2ClientCredentials(reader, builderSupplier, credentialStoresMap, xmlVersion);
                        break;
                    }
                    case "masked-resource-owner-credentials": {
                        if (!xmlVersion.isAtLeast(Version.VERSION_1_4)) {
                            throw reader.unexpectedElement();
                        }
                        builderSupplier = parseOAuth2MaskedResourceOwnerCredentials(reader, builderSupplier, xmlVersion, providersSupplier);
                        break;
                    }
                    case "masked-client-credentials": {
                        if (!xmlVersion.isAtLeast(Version.VERSION_1_4)) {
                            throw reader.unexpectedElement();
                        }
                        builderSupplier = parseOAuth2MaskedClientCredentials(reader, builderSupplier, xmlVersion, providersSupplier);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                final ExceptionSupplier<OAuth2CredentialSource.Builder, ConfigXMLParseException> finalBuilderSupplier = builderSupplier;
                return () -> finalBuilderSupplier.get().build();
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code oauth2-bearer-token-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param builderSupplier the builder supplier
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionSupplier<OAuth2CredentialSource.Builder, ConfigXMLParseException> parseOAuth2ResourceOwnerCredentials(ConfigurationXMLStreamReader reader, final ExceptionSupplier<OAuth2CredentialSource.Builder, ConfigXMLParseException> builderSupplier, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, Version xmlVersion) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        ExceptionSupplier<CredentialSource, ConfigXMLParseException> credentialSourceSupplier = null;
        XMLLocation nestedLocation = null;
        String userName = null;
        String password = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "name": {
                    if (userName != null) throw reader.unexpectedAttribute(i);
                    userName = reader.getAttributeValueResolved(i);
                    break;
                }
                case "password": {
                    if (password != null) throw reader.unexpectedAttribute(i);
                    password = reader.getAttributeValueResolved(i);
                    break;
                }
                default: throw reader.unexpectedAttribute(i);
            }
        }
        if (userName == null) throw reader.missingRequiredAttribute(xmlVersion.namespace, "name");
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                if (!xmlVersion.isAtLeast(Version.VERSION_1_1)) {
                   throw reader.unexpectedElement();
                }
                if ("credential-store-reference".equals(reader.getLocalName())) {
                    if (password != null) {
                        throw reader.unexpectedElement();
                    }
                    if (credentialSourceSupplier != null) { // must not throw because compatibility
                        xmlLog.trace("Multiple credential-store-references in resource-owner-credentials - only the last one used!");
                    }
                    nestedLocation = reader.getLocation();
                    credentialSourceSupplier = parseCredentialStoreRefType(reader, credentialStoresMap);
                } else {
                    throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                final String finalUserName = userName;
                if (password != null) {
                    final String finalPassword = password;
                    return () -> builderSupplier.get().useResourceOwnerPassword(finalUserName, finalPassword);
                }
                if (credentialSourceSupplier != null) {
                    final XMLLocation finalLocation = nestedLocation;
                    final ExceptionSupplier<CredentialSource, ConfigXMLParseException> finalCredentialSourceSupplier = credentialSourceSupplier;
                    return () -> {
                        try {
                            PasswordCredential passwordCredential = finalCredentialSourceSupplier.get().getCredential(PasswordCredential.class);
                            if (passwordCredential == null) {
                                throw new ConfigXMLParseException(xmlLog.couldNotObtainCredential(), reader);
                            }
                            char[] pass = passwordCredential.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword);
                            if (pass == null) {
                                throw new ConfigXMLParseException(xmlLog.couldNotObtainCredential(), reader);
                            }
                            String finalPassword = String.valueOf(pass);
                            return builderSupplier.get().useResourceOwnerPassword(finalUserName, finalPassword);
                        } catch (IOException e) {
                            throw xmlLog.xmlFailedToCreateCredential(finalLocation, e);
                        }
                    };
                }
                throw reader.missingRequiredAttribute(xmlVersion.namespace, "password");
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code oauth2-client-credentials-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param builderSupplier the builder supplier
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionSupplier<OAuth2CredentialSource.Builder, ConfigXMLParseException> parseOAuth2ClientCredentials(ConfigurationXMLStreamReader reader, final ExceptionSupplier<OAuth2CredentialSource.Builder, ConfigXMLParseException> builderSupplier, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap, Version xmlVersion) throws ConfigXMLParseException {
        ExceptionSupplier<CredentialSource, ConfigXMLParseException> credentialSourceSupplier = null;
        XMLLocation nestedLocation = null;
        String id = null;
        String secret = null;
        for (int i = 0; i < reader.getAttributeCount(); i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "client-id": {
                    if (id != null) throw reader.unexpectedAttribute(i);
                    id = reader.getAttributeValueResolved(i);
                    break;
                }
                case "client-secret": {
                    if (secret != null) throw reader.unexpectedAttribute(i);
                    secret = reader.getAttributeValueResolved(i);
                    break;
                }
                default: throw reader.unexpectedAttribute(i);
            }
        }
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                if (!xmlVersion.isAtLeast(Version.VERSION_1_1)) {
                    throw reader.unexpectedElement();
                }
                if ("credential-store-reference".equals(reader.getLocalName())) {
                    if (secret != null) {
                        throw reader.unexpectedElement();
                    }
                    if (credentialSourceSupplier != null) { // must not throw because compatibility
                        xmlLog.trace("Multiple credential-store-references in client-credentials - only the last one used!");
                    }
                    nestedLocation = reader.getLocation();
                    credentialSourceSupplier = parseCredentialStoreRefType(reader, credentialStoresMap);
                } else {
                    throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                if (id == null) throw reader.unexpectedContent();
                final String finalId = id;
                if (secret != null) {
                    final String finalSecret = secret;
                    return () -> builderSupplier.get().clientCredentials(finalId, finalSecret);
                }
                if (credentialSourceSupplier != null) {
                    final XMLLocation finalLocation = nestedLocation;
                    final ExceptionSupplier<CredentialSource, ConfigXMLParseException> finalCredentialSourceSupplier = credentialSourceSupplier;
                    return () -> {
                        try {
                            PasswordCredential passwordCredential = finalCredentialSourceSupplier.get().getCredential(PasswordCredential.class);
                            if (passwordCredential == null) {
                                throw new ConfigXMLParseException(xmlLog.couldNotObtainCredential(), reader);
                            }
                            char[] pass = passwordCredential.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword);
                            if (pass == null) {
                                throw new ConfigXMLParseException(xmlLog.couldNotObtainCredential(), reader);
                            }
                            String finalPassword = String.valueOf(pass);
                            return builderSupplier.get().clientCredentials(finalId, finalPassword);
                        } catch (IOException e) {
                            throw xmlLog.xmlFailedToCreateCredential(finalLocation, e);
                        }
                    };
                }
                throw reader.unexpectedContent();
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code oauth2-bearer-token-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param builderSupplier the builder supplier
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionSupplier<OAuth2CredentialSource.Builder, ConfigXMLParseException> parseOAuth2MaskedResourceOwnerCredentials(ConfigurationXMLStreamReader reader, final ExceptionSupplier<OAuth2CredentialSource.Builder, ConfigXMLParseException> builderSupplier, Version xmlVersion, Supplier<Provider[]> providers) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        XMLLocation nestedLocation = null;
        String userName = null;
        String password = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if ("name".equals(reader.getAttributeLocalName(i))) {
                if (userName != null) throw reader.unexpectedAttribute(i);
                userName = reader.getAttributeValueResolved(i);
                break;
            }
            else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (userName == null) throw reader.missingRequiredAttribute(xmlVersion.namespace, "name");
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                if ("masked-password".equals(reader.getLocalName())) {
                    if (password != null) {
                        throw reader.unexpectedElement();
                    }
                    nestedLocation = reader.getLocation();
                    Password maskedPassword = parseMaskedPassword(reader, providers).get();
                    try {
                        final PasswordFactory passwordFactory = PasswordFactory.getInstance(maskedPassword.getAlgorithm(), providers);
                        final ClearPasswordSpec spec = passwordFactory.getKeySpec(maskedPassword, ClearPasswordSpec.class);
                        password = String.valueOf(spec.getEncodedPassword());
                    } catch (InvalidKeySpecException | NoSuchAlgorithmException cause) {
                        throw xmlLog.xmlFailedToCreateCredential(nestedLocation, cause);
                    }
                } else {
                    throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                final String finalUserName = userName;
                if (password != null) {
                    final String finalPassword = password;
                    return () -> builderSupplier.get().useResourceOwnerPassword(finalUserName, finalPassword);
                }
                throw reader.missingRequiredAttribute(xmlVersion.namespace, "password");
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code oauth2-client-credentials-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param builderSupplier the builder supplier
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionSupplier<OAuth2CredentialSource.Builder, ConfigXMLParseException> parseOAuth2MaskedClientCredentials(ConfigurationXMLStreamReader reader, final ExceptionSupplier<OAuth2CredentialSource.Builder, ConfigXMLParseException> builderSupplier, Version xmlVersion,Supplier<Provider[]> providers) throws ConfigXMLParseException {
        ExceptionSupplier<CredentialSource, ConfigXMLParseException> credentialSourceSupplier = null;
        XMLLocation nestedLocation = null;
        String id = null;
        String secret = null;
        for (int i = 0; i < reader.getAttributeCount(); i ++) {
            checkAttributeNamespace(reader, i);
            if ("client-id".equals(reader.getAttributeLocalName(i))) {
                if (id != null) throw reader.unexpectedAttribute(i);
                id = reader.getAttributeValueResolved(i);
                break;
            }
            else {
                throw reader.unexpectedAttribute(i);
            }
        }
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader, xmlVersion);
                if ("masked-client-secret".equals(reader.getLocalName())) {
                    if (secret != null) {
                        throw reader.unexpectedElement();
                    }
                    nestedLocation = reader.getLocation();
                    Password maskedPassword = parseMaskedPassword(reader, providers).get();
                    try {
                        final PasswordFactory passwordFactory = PasswordFactory.getInstance(maskedPassword.getAlgorithm(), providers);
                        final ClearPasswordSpec spec = passwordFactory.getKeySpec(maskedPassword, ClearPasswordSpec.class);
                        secret = String.valueOf(spec.getEncodedPassword());
                    } catch (InvalidKeySpecException | NoSuchAlgorithmException cause) {
                        throw xmlLog.xmlFailedToCreateCredential(nestedLocation, cause);
                    }
                } else {
                    throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                if (id == null) throw reader.unexpectedContent();
                final String finalId = id;
                if (secret != null) {
                    final String finalSecret = secret;
                    return () -> builderSupplier.get().clientCredentials(finalId, finalSecret);
                }
                throw reader.unexpectedContent();
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code local-kerberos-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the clear password characters
     * @throws ConfigXMLParseException if the resource failed to be parsed or the module is not found
     */
    static CredentialSource parseLocalKerberos(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        List<Oid> mechanismOids = new LinkedList<>();
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("mechanism-names")) {
                for (String name : reader.getListAttributeValueAsArrayResolved(i)) {
                    String oid = OidsUtil.attributeNameToOid(OidsUtil.Category.GSS, name);
                    if (oid == null) {
                        throw xmlLog.xmlInvalidGssMechanismName(reader, name);
                    }
                    try {
                        mechanismOids.add(new Oid(oid));
                    } catch (GSSException e) {
                        throw xmlLog.xmlGssMechanismOidConversionFailed(reader, oid, e);
                    }
                }
            } else if (reader.getAttributeLocalName(i).equals("mechanism-oids")) {
                for (String oid : reader.getListAttributeValueAsArrayResolved(i)) {
                    try {
                        mechanismOids.add(new Oid(oid));
                    } catch (GSSException e) {
                        throw xmlLog.xmlGssMechanismOidConversionFailed(reader, oid, e);
                    }
                }
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (mechanismOids.size() == 0) {
            mechanismOids.add(GSSCredentialSecurityFactory.KERBEROS_V5);
            mechanismOids.add(GSSCredentialSecurityFactory.SPNEGO);
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return LocalKerberosCredentialSource.builder().setMechanismOids(mechanismOids.toArray(new Oid[mechanismOids.size()])).build();
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    // util

    private static String checkGetElementNamespace(final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        String namespaceUri = reader.getNamespaceURI();
        if (! KNOWN_NAMESPACES.containsKey(namespaceUri)) {
            throw reader.unexpectedElement();
        }
        return namespaceUri;
    }

    private static void checkElementNamespace(final ConfigurationXMLStreamReader reader, final Version xmlVersion) throws ConfigXMLParseException {
        if (! xmlVersion.namespace.equals(reader.getNamespaceURI())) {
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

    private static String requireSingleAttribute(final ConfigurationXMLStreamReader reader, final String attributeName) throws ConfigXMLParseException {
        return requireSingleAttribute(reader, attributeName, (ExceptionSupplier<String, ConfigXMLParseException>) () -> reader.getAttributeValueResolved(0));
    }

    private static URI requireSingleURIAttribute(final ConfigurationXMLStreamReader reader, final String attributeName) throws ConfigXMLParseException {
        return requireSingleAttribute(reader, attributeName, () -> reader.getURIAttributeValueResolved(0));
    }

    private static <A> A requireSingleAttribute(final ConfigurationXMLStreamReader reader, final String attributeName, ExceptionSupplier<A, ConfigXMLParseException> attributeFunction) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount < 1) {
            throw reader.missingRequiredAttribute("", attributeName);
        }
        checkAttributeNamespace(reader, 0);
        if (! reader.getAttributeLocalName(0).equals(attributeName)) {
            throw reader.unexpectedAttribute(0);
        }
        if (attributeCount > 1) {
            throw reader.unexpectedAttribute(1);
        }
        return attributeFunction.get();
    }

    private static ConfigXMLParseException missingAttribute(final ConfigurationXMLStreamReader reader, final String name) {
        return reader.missingRequiredAttribute(null, name);
    }

    private static ConfigXMLParseException invalidPortNumber(final ConfigurationXMLStreamReader reader, final int index) throws ConfigXMLParseException {
        return xmlLog.xmlInvalidPortNumber(reader, reader.getAttributeValueResolved(index), reader.getAttributeLocalName(index), reader.getName());
    }

    static final class KeyStoreCreateFactory implements ExceptionSupplier<KeyStore, ConfigXMLParseException> {
        private final String providerName;
        private final Supplier<Provider[]> providers;
        private final String type;
        private final XMLLocation location;

        KeyStoreCreateFactory(final Supplier<Provider[]> providers, final String providerName, final String type, final XMLLocation location) {
            this.providerName = providerName;
            this.providers = providers;
            this.type = type;
            this.location = location;
        }

        public KeyStore get() throws ConfigXMLParseException {
            Provider provider = findProvider(providers, providerName, KeyStore.class, type);
            if (provider == null) {
                throw xmlLog.xmlUnableToIdentifyProvider(location, providerName, "KeyStore", type);
            }
            try {
                return KeyStore.getInstance(type, provider);
            } catch (GeneralSecurityException e) {
                throw xmlLog.xmlFailedToCreateKeyStore(location, e);
            }
        }
    }

    static final class UnknownTypeFileKeyStoreFactory implements ExceptionSupplier<KeyStore, ConfigXMLParseException> {
        private final String providerName;
        private final Supplier<Provider[]> providers;
        private final XMLLocation location;
        protected final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory;
        private final String fileName;
        private final ExceptionSupplier<InputStream, IOException> resourceSupplier;
        private final URI uri;

        UnknownTypeFileKeyStoreFactory(final Supplier<Provider[]> providers, final String providerName, final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory, final String fileName, final ExceptionSupplier<InputStream, IOException> resourceSupplier, final URI uri, final XMLLocation location) {
            this.providerName = providerName;
            this.providers = providers;
            this.location = location;
            this.passwordFactory = passwordFactory;
            this.fileName = fileName;
            this.resourceSupplier = resourceSupplier;
            this.uri = uri;
        }

        @Override
        public KeyStore get() throws ConfigXMLParseException {
            KeyStore keyStore = null;
            try {
                FileInputStream fin = null;
                if (fileName != null) {
                    fin = new FileInputStream(fileName);
                } else if (resourceSupplier != null) {
                    InputStream is = resourceSupplier.get();
                    if (is instanceof FileInputStream) {
                        fin = (FileInputStream) is;
                    }
                } else {
                    fin = new FileInputStream(uri.toURL().getFile());
                }
                keyStore = KeyStoreUtil.loadKeyStore(providers, providerName, fin, fileName, passwordFactory.get());
            } catch (Exception e) {
                throw xmlLog.xmlFailedToCreateKeyStore(location, e);
            }
            return keyStore;
        }
    }

    static final class PasswordKeyStoreFactory implements ExceptionSupplier<KeyStore, ConfigXMLParseException> {
        private final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory;

        PasswordKeyStoreFactory(final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory) {
            this.delegateFactory = delegateFactory;
        }

        public KeyStore get() throws ConfigXMLParseException {
            return new WrappingPasswordKeyStore(delegateFactory.get());
        }
    }

    abstract static class AbstractLoadingKeyStoreFactory implements ExceptionSupplier<KeyStore, ConfigXMLParseException> {

        protected final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory;
        protected final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory;
        protected final XMLLocation location;

        protected AbstractLoadingKeyStoreFactory(final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory, final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory, final XMLLocation location) {
            this.delegateFactory = delegateFactory;
            this.passwordFactory = passwordFactory;
            this.location = location;
        }

        public KeyStore get() throws ConfigXMLParseException {
            try {
                KeyStore keyStore = delegateFactory.get();
                try (InputStream fis = createStream()) {
                    keyStore.load(fis, passwordFactory == null ? null : passwordFactory.get());
                }
                return keyStore;
            } catch (GeneralSecurityException | IOException e) {
                throw xmlLog.xmlFailedToLoadKeyStoreData(location, e);
            }
        }

        abstract InputStream createStream() throws IOException;
    }

    static final class FileLoadingKeyStoreFactory extends AbstractLoadingKeyStoreFactory {

        private final String fileName;

        FileLoadingKeyStoreFactory(final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory, final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory, final String fileName, final XMLLocation location) {
            super(delegateFactory, passwordFactory, location);
            this.fileName = fileName;
        }

        InputStream createStream() throws FileNotFoundException {
            return new FileInputStream(fileName);
        }
    }

    static final class ResourceLoadingKeyStoreFactory extends AbstractLoadingKeyStoreFactory {

        private final ExceptionSupplier<InputStream, IOException> resourceSupplier;

        ResourceLoadingKeyStoreFactory(final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory, final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory, final ExceptionSupplier<InputStream, IOException> resourceSupplier, final XMLLocation location) {
            super(delegateFactory, passwordFactory, location);
            this.resourceSupplier = resourceSupplier;
        }

        InputStream createStream() throws IOException {
            return resourceSupplier.get();
        }
    }

    static final class URILoadingKeyStoreFactory extends AbstractLoadingKeyStoreFactory {
        private final URI uri;

        URILoadingKeyStoreFactory(final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory, final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory, final URI uri, final XMLLocation location) {
            super(delegateFactory, passwordFactory, location);
            this.uri = uri;
        }

        InputStream createStream() throws IOException {
            return uri.toURL().openStream();
        }
    }

    static final class NullLoadingKeyStoreFactory extends AbstractLoadingKeyStoreFactory {

        NullLoadingKeyStoreFactory(final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory, final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory, final XMLLocation location) {
            super(delegateFactory, passwordFactory, location);
        }

        @Override
        InputStream createStream() throws IOException {
            return null;
        }

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
