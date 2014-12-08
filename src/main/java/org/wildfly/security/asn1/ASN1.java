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

package org.wildfly.security.asn1;

/**
 * A class that contains ASN.1 constants.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class ASN1 {

    /**
     * The universal integer type tag.
     */
    public static final int INTEGER_TYPE = 2;

    /**
     * The universal bit string type tag.
     */
    public static final int BIT_STRING_TYPE = 3;

    /**
     * The universal octet string type tag.
     */
    public static final int OCTET_STRING_TYPE = 4;

    /**
     * The universal null type tag.
     */
    public static final int NULL_TYPE = 5;

    /**
     * The universal object identifier type tag.
     */
    public static final int OBJECT_IDENTIFIER_TYPE = 6;

    /**
     * The universal IA5 string type tag.
     */
    public static final int IA5_STRING_TYPE = 22;

    /**
     * The universal sequence type tag.
     */
    public static final int SEQUENCE_TYPE = 48;

    /**
     * The universal set type tag.
     */
    public static final int SET_TYPE = 49;

    /**
     * Mask used to determine if a type tag is constructed.
     */
    public static final int CONSTRUCTED_MASK = 0x20;

    /**
     * Mask used to obtain the class bits from a type tag.
     */
    public static final int CLASS_MASK = 0xc0;

    /**
     * Mask used to obtain the tag number bits from a type tag.
     */
    public static final int TAG_NUMBER_MASK = 0x1f;
}
