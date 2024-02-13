/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.util;

import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.client.config.ConfigurationXMLStreamReader;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.common.function.ExceptionUnaryOperator;

import java.net.URI;

/**
 * A utility class to get and check information about attributes in XML file.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */

public class XMLParserUtils {

    public static boolean isSet(int var, int bit) {
        return (var & 1 << bit) != 0;
    }

    public static int setBit(int var, int bit) {
        return var | 1 << bit;
    }

    public static void checkAttributeNamespace(final ConfigurationXMLStreamReader reader, final int idx) throws ConfigXMLParseException {
        final String attributeNamespace = reader.getAttributeNamespace(idx);
        if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
            throw reader.unexpectedAttribute(idx);
        }
    }

    public static void requireNoAttributes(final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount > 0) {
            throw reader.unexpectedAttribute(0);
        }
    }

    public static String requireSingleAttribute(final ConfigurationXMLStreamReader reader, final String attributeName) throws ConfigXMLParseException {
        return requireSingleAttribute(reader, attributeName, (ExceptionSupplier<String, ConfigXMLParseException>) () -> reader.getAttributeValueResolved(0));
    }

    public static URI requireSingleURIAttribute(final ConfigurationXMLStreamReader reader, final String attributeName) throws ConfigXMLParseException {
        return requireSingleAttribute(reader, attributeName, () -> reader.getURIAttributeValueResolved(0));
    }

    public static <A> A requireSingleAttribute(final ConfigurationXMLStreamReader reader, final String attributeName, ExceptionSupplier<A, ConfigXMLParseException> attributeFunction) throws ConfigXMLParseException {
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

    public static ConfigXMLParseException missingAttribute(final ConfigurationXMLStreamReader reader, final String name) {
        return reader.missingRequiredAttribute(null, name);
    }

    public static <T, E extends Exception> ExceptionUnaryOperator<T, E> andThenOp(ExceptionUnaryOperator<T, E> first, ExceptionUnaryOperator<T, E> second) {
        return t -> second.apply(first.apply(t));
    }
}
