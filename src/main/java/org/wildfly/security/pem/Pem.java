/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.pem;

import static org.wildfly.security._private.ElytronMessages.log;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.function.BiFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.wildfly.common.Assert;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.CodePointIterator;

/**
 * A class containing utilities which can handle the PEM format.  See <a href="https://tools.ietf.org/html/rfc7468">RFC 7468</a>
 * for more information.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class Pem {
    private static final Pattern VALID_LABEL = Pattern.compile("[^ -~&&[^-]]");

    /**
     * Parse arbitrary PEM content.  The given function is used to parse the content of the PEM representation and produce
     * some result.  The PEM type string is passed to the function.  If the function throws an exception, that exception
     * is propagated to the caller of this method.  If the PEM content is malformed, an exception is thrown.  If the
     * trailing PEM content is found to be invalid after the function returns, the function result is discarded and an
     * exception is thrown.
     *
     * @param pemContent the content to parse (must not be {@code null})
     * @param contentFunction a function to consume the PEM content and produce a result (must not be {@code null})
     * @param <R> the value return type
     * @return the return value of the function
     * @throws IllegalArgumentException if there is a problem with processing the content of the PEM data
     */
    public static <R> R parsePemContent(CodePointIterator pemContent, BiFunction<String, ByteIterator, R> contentFunction) throws IllegalArgumentException {
        Assert.checkNotNullParam("pemContent", pemContent);
        Assert.checkNotNullParam("contentFunction", contentFunction);
        if (! pemContent.contentEquals("-----BEGIN ")) {
            throw log.malformedPemContent(pemContent.offset());
        }
        String type = pemContent.delimitedBy('-').drainToString().trim();
        final Matcher matcher = VALID_LABEL.matcher(type);
        if (matcher.find()) {
            // BEGIN string is 11 chars long
            throw log.malformedPemContent(matcher.start() + 11);
        }
        if (! pemContent.contentEquals("-----")) {
            throw log.malformedPemContent(pemContent.offset());
        }
        final ByteIterator byteIterator = pemContent.delimitedBy('-').base64Decode();
        final R result = contentFunction.apply(type, byteIterator);
        if (! pemContent.contentEquals("-----END ")) {
            throw log.malformedPemContent(pemContent.offset());
        }
        if (! pemContent.contentEquals(type)) {
            throw log.malformedPemContent(pemContent.offset());
        }
        if (! pemContent.contentEquals("-----")) {
            throw log.malformedPemContent(pemContent.offset());
        }
        return result;
    }

    /**
     * Generate PEM content to the given byte string builder.  The appropriate header and footer surrounds the base-64
     * encoded value.
     *
     * @param target the target byte string builder (must not be {@code null})
     * @param type the content type (must not be {@code null})
     * @param content the content iterator (must not be {@code null})
     * @throws IllegalArgumentException if there is a problem with the data or the type
     */
    public static void generatePemContent(ByteStringBuilder target, String type, ByteIterator content) throws IllegalArgumentException {
        Assert.checkNotNullParam("target", target);
        Assert.checkNotNullParam("type", type);
        Assert.checkNotNullParam("content", content);
        final Matcher matcher = VALID_LABEL.matcher(type);
        if (matcher.find()) {
            throw log.invalidPemType("<any valid PEM type>", type);
        }
        target.append("-----BEGIN ").append(type).append("-----\n");
        target.append(content.base64Encode().drainToString('\n', 64));
        target.append("\n-----END ").append(type).append("-----\n");
    }

    private static X509Certificate parsePemX509CertificateContent(String type, ByteIterator content) throws IllegalArgumentException {
        if (! type.equals("CERTIFICATE")) {
            throw log.invalidPemType("CERTIFICATE", type);
        }
        try {
            final CertificateFactory instance = CertificateFactory.getInstance("X.509");
            return (X509Certificate) instance.generateCertificate(content.asInputStream());
        } catch (CertificateException e) {
            throw log.certificateParseError(e);
        }
    }

    /**
     * Parse an X.509 certificate in PEM format.
     *
     * @param pemContent the PEM content (must not be {@code null})
     * @return the certificate (not {@code null})
     * @throws IllegalArgumentException if the certificate could not be parsed for some reason
     */
    public static X509Certificate parsePemX509Certificate(CodePointIterator pemContent) throws IllegalArgumentException {
        Assert.checkNotNullParam("pemContent", pemContent);
        return parsePemContent(pemContent, Pem::parsePemX509CertificateContent);
    }

    /**
     * Generate PEM content containing an X.509 certificate.
     *
     * @param target the target byte string builder (must not be {@code null})
     * @param certificate the X.509 certificate (must not be {@code null})
     */
    public static void generatePemX509Certificate(ByteStringBuilder target, X509Certificate certificate) {
        Assert.checkNotNullParam("target", target);
        Assert.checkNotNullParam("certificate", certificate);
        try {
            generatePemContent(target, "CERTIFICATE", ByteIterator.ofBytes(certificate.getEncoded()));
        } catch (CertificateEncodingException e) {
            throw log.certificateParseError(e);
        }
    }
}
