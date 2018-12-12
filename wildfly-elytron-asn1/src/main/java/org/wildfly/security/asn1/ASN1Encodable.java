/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.asn1;

import java.math.BigInteger;

import org.wildfly.common.Assert;

/**
 * An object which can be encoded into an {@linkplain ASN1Encoder ASN.1 encoder}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface ASN1Encodable {
    /**
     * Encode this object.
     *
     * @param encoder the encoder (must not be {@code null})
     */
    void encodeTo(ASN1Encoder encoder);

    /**
     * Create an instance that will encode the given string as UTF-8.
     *
     * @param string the string to encode (must not be {@code null})
     * @return the instance
     */
    static ASN1Encodable ofUtf8String(String string) {
        Assert.checkNotNullParam("string", string);
        return e -> e.encodeUTF8String(string);
    }

    /**
     * Create an instance that will encode the given string as BMP (UTF-16BE).
     *
     * @param string the string to encode (must not be {@code null})
     * @return the instance
     */
    static ASN1Encodable ofBMPString(String string) {
        Assert.checkNotNullParam("string", string);
        return e -> e.encodeBMPString(string);
    }

    /**
     * Create an instance that will encode the given string as universal (UTF-32BE).
     *
     * @param string the string to encode (must not be {@code null})
     * @return the instance
     */
    static ASN1Encodable ofUniversalString(String string) {
        Assert.checkNotNullParam("string", string);
        return e -> e.encodeUniversalString(string);
    }

    /**
     * Create an instance that will encode the given string in IA5 form.
     *
     * @param string the string to encode (must not be {@code null})
     * @return the instance
     */
    static ASN1Encodable ofIA5String(String string) {
        Assert.checkNotNullParam("string", string);
        return e -> e.encodeIA5String(string);
    }

    /**
     * Create an instance that will encode the given string in "printable" form.
     *
     * @param string the string to encode (must not be {@code null})
     * @return the instance
     */
    static ASN1Encodable ofPrintableString(String string) {
        Assert.checkNotNullParam("string", string);
        return e -> e.encodePrintableString(string);
    }

    /**
     * Create an instance that will encode the given integer.
     *
     * @param value the integer to encode
     * @return the instance
     */
    static ASN1Encodable ofInteger(int value) {
        return e -> e.encodeInteger(value);
    }

    /**
     * Create an instance that will encode the given integer.
     *
     * @param value the integer to encode (must not be {@code null})
     * @return the instance
     */
    static ASN1Encodable ofInteger(BigInteger value) {
        Assert.checkNotNullParam("value", value);
        return e -> e.encodeInteger(value);
    }

    /**
     * Create an instance that will encode the given object identifier.
     *
     * @param oid the object identifier to encode (must not be {@code null})
     * @return the instance
     */
    static ASN1Encodable ofOid(String oid) {
        Assert.checkNotNullParam("oid", oid);
        return e -> e.encodeObjectIdentifier(oid);
    }

    /**
     * Create an instance that will write the given encoded bytes.
     *
     * @param bytes the bytes to write (must not be {@code null})
     * @return the instance
     */
    static ASN1Encodable ofEncodedBytes(byte[] bytes) {
        Assert.checkNotNullParam("bytes", bytes);
        return e -> e.writeEncoded(bytes);
    }
}
