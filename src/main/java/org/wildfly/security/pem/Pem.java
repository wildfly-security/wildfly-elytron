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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.function.BiFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.CodePointIterator;
import org.wildfly.security.x500.cert.PKCS10CertificateSigningRequest;

/**
 * A class containing utilities which can handle the PEM format.  See <a href="https://tools.ietf.org/html/rfc7468">RFC 7468</a>
 * for more information.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class Pem {
    private static final Pattern VALID_LABEL = Pattern.compile("[^ -~&&[^-]]");
    private static final String PUBLIC_KEY_FORMAT = "PUBLIC KEY";
    private static final String CERTIFICATE_FORMAT = "CERTIFICATE";
    private static final String PRIVATE_KEY_FORMAT = "PRIVATE KEY";
    private static final String CERTIFICATE_REQUEST_FORMAT = "CERTIFICATE REQUEST";

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
     * @return the return value of the function or {@code null} if there is no PEM content to parse
     * @throws IllegalArgumentException if there is a problem with processing the content of the PEM data
     */
    public static <R> R parsePemContent(CodePointIterator pemContent, BiFunction<String, ByteIterator, R> contentFunction) throws IllegalArgumentException {
        Assert.checkNotNullParam("pemContent", pemContent);
        Assert.checkNotNullParam("contentFunction", contentFunction);

        while(true) {
            if (! pemContent.hasNext()) return null;
            int cp = pemContent.next();
            if (cp == '-') break;
            if (! Character.isWhitespace(cp)) {
                throw log.malformedPemContent(pemContent.offset());
            }
        }

        if (! pemContent.limitedTo(10).contentEquals("----BEGIN ")) {
            throw log.malformedPemContent(pemContent.offset());
        }
        String type = pemContent.delimitedBy('-').drainToString();
        final Matcher matcher = VALID_LABEL.matcher(type);
        if (matcher.find()) {
            // BEGIN string is 11 chars long
            throw log.malformedPemContent(matcher.start() + 11);
        }
        if (! pemContent.limitedTo(5).contentEquals("-----")) {
            throw log.malformedPemContent(pemContent.offset());
        }
        CodePointIterator delimitedIterator = pemContent.delimitedBy('-').skip(Character::isWhitespace).skipCrLf();
        final ByteIterator byteIterator = delimitedIterator.base64Decode();
        final R result = contentFunction.apply(type, byteIterator);
        delimitedIterator.skipAll(); // skip until '-'

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
                    next = parsePemContent(pemContent, (type, byteIterator) -> {
                        switch (type) {
                            case CERTIFICATE_FORMAT: {
                                final X509Certificate x509Certificate = parsePemX509CertificateContent(type, byteIterator);
                                return new PemEntry<>(x509Certificate);
                            }
                            case PUBLIC_KEY_FORMAT: {
                                final PublicKey publicKey = parsePemPublicKey(type, byteIterator);
                                return new PemEntry<>(publicKey);
                            }
                            case PRIVATE_KEY_FORMAT: {
                                final PrivateKey privateKey = parsePemPrivateKey(type, byteIterator);
                                return new PemEntry<>(privateKey);
                            }
                            default: {
                                throw log.malformedPemContent(pemContent.offset());
                            }
                        }
                    });
                    if (next == null) {
                        return false;
                    }
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

    /**
     * Extracts the DER content from the given <code>pemContent</code>.
     *
     * @param pemContent a {@link CodePointIterator} with the PEM content
     * @return a byte array with the DER content
     */
    public static byte[] extractDerContent(CodePointIterator pemContent) {
        return parsePemContent(pemContent, (type, byteIterator) -> byteIterator.drain());
    }

    private static X509Certificate parsePemX509CertificateContent(String type, ByteIterator byteIterator) throws IllegalArgumentException {
        if (! type.equals(CERTIFICATE_FORMAT)) {
            throw log.invalidPemType(CERTIFICATE_FORMAT, type);
        }
        try {
            final CertificateFactory instance = CertificateFactory.getInstance("X.509");
            return (X509Certificate) instance.generateCertificate(byteIterator.asInputStream());
        } catch (CertificateException e) {
            throw log.certificateParseError(e);
        }
    }

    private static PublicKey parsePemPublicKey(String type, ByteIterator byteIterator) throws IllegalArgumentException {
        if (! type.equals(PUBLIC_KEY_FORMAT)) {
            throw log.invalidPemType(PUBLIC_KEY_FORMAT, type);
        }
        try {
            byte[] der = byteIterator.drain();
            DERDecoder derDecoder = new DERDecoder(der);
            derDecoder.startSequence();
            switch (derDecoder.peekType()) {
                case ASN1.SEQUENCE_TYPE:
                    derDecoder.startSequence();
                    String algorithm = derDecoder.decodeObjectIdentifierAsKeyAlgorithm();

                    if (algorithm != null) {
                        return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(der));
                    }

                    throw log.asnUnrecognisedAlgorithm(algorithm);
                default:
                    throw log.asnUnexpectedTag();
            }
        } catch (Exception cause) {
            throw log.publicKeyParseError(cause);
        }
    }

    private static PrivateKey parsePemPrivateKey(String type, ByteIterator byteIterator) throws IllegalArgumentException {
        if (! type.equals(PRIVATE_KEY_FORMAT)) {
            throw log.invalidPemType(PRIVATE_KEY_FORMAT, type);
        }
        try {
            byte[] der = byteIterator.drain();
            DERDecoder derDecoder = new DERDecoder(der);
            derDecoder.startSequence();

            // Version
            if (derDecoder.peekType() != ASN1.INTEGER_TYPE) throw log.asnUnexpectedTag();
            derDecoder.skipElement();

            // AlgorithmIdentifier
            derDecoder.startSequence();
            String algorithm = derDecoder.decodeObjectIdentifierAsKeyAlgorithm();

            if (algorithm != null) {
                return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
            }

            throw log.asnUnrecognisedAlgorithm(algorithm);
        } catch (Exception cause) {
            throw log.privateKeyParseError(cause);
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
            generatePemContent(target, CERTIFICATE_FORMAT, ByteIterator.ofBytes(certificate.getEncoded()));
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
        try {
            KeyFactory instance = KeyFactory.getInstance(publicKey.getAlgorithm());
            X509EncodedKeySpec keySpec = instance.getKeySpec(publicKey, X509EncodedKeySpec.class);
            generatePemContent(target, PUBLIC_KEY_FORMAT, ByteIterator.ofBytes(keySpec.getEncoded()));
        } catch (Exception e) {
            throw log.publicKeyParseError(e);
        }
    }

    /**
     * Generate PEM content containing a PKCS #10 certificate signing request.
     *
     * @param target the target byte string builder (must not be {@code null})
     * @param certificateSigningRequest the PKCS #10 certificate signing request (must not be {@code null})
     * @since 1.2.0
     */
    public static void generatePemPKCS10CertificateSigningRequest(ByteStringBuilder target, PKCS10CertificateSigningRequest certificateSigningRequest) {
        Assert.checkNotNullParam("target", target);
        Assert.checkNotNullParam("certificateSigningRequest", certificateSigningRequest);
        generatePemContent(target, CERTIFICATE_REQUEST_FORMAT, ByteIterator.ofBytes(certificateSigningRequest.getEncoded()));
    }
}
