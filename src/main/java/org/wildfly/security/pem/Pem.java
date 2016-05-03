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

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Iterator;
import java.util.NoSuchElementException;
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
        if (! pemContent.limitedTo(11).contentEquals("-----BEGIN ")) {
            throw log.malformedPemContent(pemContent.offset());
        }
        String type = pemContent.delimitedBy('-').drainToString().trim();
        final Matcher matcher = VALID_LABEL.matcher(type);
        if (matcher.find()) {
            // BEGIN string is 11 chars long
            throw log.malformedPemContent(matcher.start() + 11);
        }
        if (! pemContent.limitedTo(5).contentEquals("-----")) {
            throw log.malformedPemContent(pemContent.offset());
        }

        String encodedKey = pemContent.delimitedBy('-').drainToString();

        encodedKey = encodedKey.replaceAll("\r\n", "");
        encodedKey = encodedKey.replaceAll("\n", "");
        encodedKey = encodedKey.trim();

        final ByteIterator byteIterator = ByteIterator.ofBytes(encodedKey.getBytes()).base64Decode();
        final R result = contentFunction.apply(type, byteIterator);
        if (! pemContent.limitedTo(9).contentEquals("-----END ")) {
            throw log.malformedPemContent(pemContent.offset());
        }
        if (! pemContent.limitedTo(type.length()).contentEquals(type)) {
            throw log.malformedPemContent(pemContent.offset());
        }
        if (! pemContent.limitedTo(5).contentEquals("-----")) {
            throw log.malformedPemContent(pemContent.offset());
        }
        return result;
    }

    /**
     * Iterate over the contents of a PEM file, returning each entry in sequence.
     *
     * @param pemContent the code point iterator over the content (must not be {@code null})
     * @return the iterator (not {@code null})
     */
    public static Iterator<PemEntry<?>> parsePemContent(CodePointIterator pemContent) {
        return new Iterator<PemEntry<?>>() {
            private PemEntry<?> next;

            public boolean hasNext() {
                if (next == null) {
                    if (! pemContent.hasNext()) {
                        return false;
                    }
                    next = parsePemContent(pemContent, (label, byteIterator) -> {
                        switch (label) {
                            case "CERTIFICATE": {
                                final X509Certificate x509Certificate = parsePemX509CertificateContent(label, byteIterator);
                                return new PemEntry<>(x509Certificate);
                            }
                            case "PUBLIC KEY": {
                                final PublicKey publicKey = parsePemPublicKey(label, byteIterator);
                                return new PemEntry<>(publicKey);
                            }
                            default: {
                                throw log.malformedPemContent(pemContent.offset());
                            }
                        }
                    });
                }
                return true;
            }

            public PemEntry<?> next() {
                if (! hasNext()) {
                    throw new NoSuchElementException();
                }
                try {
                    return next;
                } finally {
                    next = null;
                }
            }
        };
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

    private static PublicKey parsePemPublicKey(String type, ByteIterator content) throws IllegalArgumentException {
        if (! type.equals("PUBLIC KEY")) {
            throw log.invalidPemType("PUBLIC KEY", type);
        }
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(content.drain());
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException(e);
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
     * Parse a {@link PublicKey} in PEM format.
     *
     * @param pemContent the PEM content (must not be {@code null})
     * @return the public key (not {@code null})
     * @throws IllegalArgumentException if the public key could not be parsed for some reason
     */
    public static PublicKey parsePemPublicKey(CodePointIterator pemContent) throws IllegalArgumentException {
        Assert.checkNotNullParam("pemContent", pemContent);
        return parsePemContent(pemContent, Pem::parsePemPublicKey);
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

    /**
     * Generate PEM content containing a {@link PublicKey}.
     *
     * @param target the target byte string builder (must not be {@code null})
     * @param publicKey the {@link PublicKey} (must not be {@code null})
     */
    public static void generatePemPublicKey(ByteStringBuilder target, PublicKey publicKey) {
        Assert.checkNotNullParam("target", target);
        Assert.checkNotNullParam("publicKey", publicKey);

        generatePemContent(target, "PUBLIC KEY", ByteIterator.ofBytes(publicKey.getEncoded()));
    }
}
