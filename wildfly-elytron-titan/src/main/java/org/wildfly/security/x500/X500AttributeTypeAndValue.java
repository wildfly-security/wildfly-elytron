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

package org.wildfly.security.x500;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.asn1.ASN1Encoder;

/**
 * An X.500 directory attribute, which is comprised of an attribute type OID and a single values, whose type is
 * defined by the attribute type.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X500AttributeTypeAndValue implements ASN1Encodable {
    private final String attributeType;
    private final ASN1Encodable value;

    private X500AttributeTypeAndValue(final String attributeType, final ASN1Encodable value) {
        this.attributeType = attributeType;
        this.value = value;
    }

    /**
     * Construct a new instance with the given value.
     *
     * @param attributeType the attribute type OID (must not be {@code null})
     * @param value the single value (must not be {@code null})
     * @return the directory attribute
     */
    public static X500AttributeTypeAndValue create(final String attributeType, ASN1Encodable value) {
        Assert.checkNotNullParam("attributeType", attributeType);
        Assert.checkNotNullParam("value", value);
        return new X500AttributeTypeAndValue(attributeType, value);
    }

    /**
     * Construct a new instance with a UTF-8 value.
     *
     * @param attributeType the attribute type OID (must not be {@code null})
     * @param stringValue the string value (must not be {@code null})
     * @return the directory attribute
     */
    public static X500AttributeTypeAndValue createUtf8(final String attributeType, String stringValue) {
        Assert.checkNotNullParam("stringValue", stringValue);
        return create(attributeType, ASN1Encodable.ofUtf8String(stringValue));
    }

    /**
     * Construct a new instance with an OID value.
     *
     * @param attributeType the attribute type OID (must not be {@code null})
     * @param oid the OID (must not be {@code null})
     * @return the directory attribute
     */
    public static X500AttributeTypeAndValue createObjectId(final String attributeType, String oid) {
        return create(attributeType, ASN1Encodable.ofOid(oid));
    }

    public void encodeTo(final ASN1Encoder encoder) {
        encoder.startSequence();
        encoder.encodeObjectIdentifier(attributeType);
        value.encodeTo(encoder);
        encoder.endSequence();
    }
}
