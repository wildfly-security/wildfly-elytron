package org.wildfly.security.auth.client;

import org.wildfly.security.provider.util.ProviderFactory;
import org.wildfly.security.provider.util.ProviderUtil;

import java.security.Provider;
import java.util.Collections;
import java.util.HashMap;
import java.util.function.Supplier;
import java.util.Map;

import static org.wildfly.security.provider.util.ProviderUtil.INSTALLED_PROVIDERS;


public class EncryptedExpressionsXmlParser {

    private static final Supplier<Provider[]> PROVIDER_SUPPLIER = ProviderFactory.getElytronProviderSupplier(EncryptedExpressionsXmlParser.class.getClassLoader());

    private static final Supplier<Provider[]> DEFAULT_PROVIDER_SUPPLIER = ProviderUtil.aggregate(PROVIDER_SUPPLIER, INSTALLED_PROVIDERS);

    static final Map<String, Version> KNOWN_NAMESPACES;

    private enum Version {

        VERSION_1_0("urn:encrypted:expression:1.0", null);
        final String nameSpace;
        final Version parent;

        Version(String nameSpace, Version parent) {
            this.nameSpace = nameSpace;
            this.parent = parent;
        }
    }

    static {
        Map<String, Version> knownNamespaces = new HashMap<>();
        for (Version version : Version.values()) {
            knownNamespaces.put(version.nameSpace, version);
        }
        KNOWN_NAMESPACES = Collections.unmodifiableMap(knownNamespaces);
    }

    private EncryptedExpressionsXmlParser() {
    }

    public static void parseEncryptedExpressionClientConfiguration() {

    }
}
