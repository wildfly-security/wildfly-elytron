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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.DEREncoder;

/**
 * A builder for X.500 principals, defined in RFC 5280 as:
 *
 * <pre>
    Name ::= CHOICE { -- only one possibility for now --
      rdnSequence  RDNSequence }

    RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

    RelativeDistinguishedName ::=
      SET SIZE (1..MAX) OF AttributeTypeAndValue

    AttributeTypeAndValue ::= SEQUENCE {
      type     AttributeType,
      value    AttributeValue }

    AttributeType ::= OBJECT IDENTIFIER

    AttributeValue ::= ANY -- DEFINED BY AttributeType

    DirectoryString ::= CHOICE {
          teletexString           TeletexString (SIZE (1..MAX)),
          printableString         PrintableString (SIZE (1..MAX)),
          universalString         UniversalString (SIZE (1..MAX)),
          utf8String              UTF8String (SIZE (1..MAX)),
          bmpString               BMPString (SIZE (1..MAX)) }
 * </pre>
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X500PrincipalBuilder {
    private final List<Collection<X500AttributeTypeAndValue>> items = new ArrayList<>();

    /**
     * Construct a new instance.
     */
    public X500PrincipalBuilder() {
    }

    /**
     * Add a single item to the builder.
     *
     * @param attributeTypeAndValue the attribute-value pair (must not be {@code null})
     * @return this builder instance
     */
    public X500PrincipalBuilder addItem(X500AttributeTypeAndValue attributeTypeAndValue) {
        Assert.checkNotNullParam("attributeTypeAndValue", attributeTypeAndValue);
        items.add(Collections.singletonList(attributeTypeAndValue));
        return this;
    }

    /**
     * Add a compound item to the builder.
     *
     * @param attributeTypeAndValues the collection of attribute-value pairs (must not be {@code null})
     * @return this builder instance
     */
    public X500PrincipalBuilder addCompoundItem(Collection<X500AttributeTypeAndValue> attributeTypeAndValues) {
        Assert.checkNotNullParam("attributeTypeAndValues", attributeTypeAndValues);
        Assert.checkNotEmptyParam("attributeTypeAndValues", attributeTypeAndValues);
        items.add(attributeTypeAndValues);
        return this;
    }

    /**
     * Build the principal.  On return (with any outcome), this builder is re-set for building a new principal.
     *
     * @return the constructed principal (not {@code null})
     * @throws IllegalArgumentException if the principal is somehow invalid
     */
    public X500Principal build() throws IllegalArgumentException {
        final DEREncoder derEncoder = new DEREncoder();
        derEncoder.startSequence();
        for (Collection<X500AttributeTypeAndValue> itemSet : items) {
            derEncoder.startSet();
            for (X500AttributeTypeAndValue item : itemSet) {
                item.encodeTo(derEncoder);
            }
            derEncoder.endSet();
        }
        derEncoder.endSequence();
        return new X500Principal(derEncoder.getEncoded());
    }
}
