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
 * An interface for decoding ASN.1 encoded values from an input stream.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public interface ASN1Decoder {

    /**
     * Start decoding an ASN.1 sequence. All subsequent decode operations will decode
     * elements from this sequence until {@link #endSequence()} is called.
     *
     * @throws ASN1Exception if the next element is not a sequence
     */
    void startSequence() throws ASN1Exception;

    /**
     * Advance to the end of a sequence. If there are any elements in the sequence that have
     * not yet been decoded, they will be discarded.
     *
     * @throws ASN1Exception if an error occurs while advancing to the end of the sequence
     */
    void endSequence() throws ASN1Exception;

    /**
     * Starting decoding an ASN.1 set. All subsequent decode operations will decode
     * elements from this set until {@link #endSet()} is called.
     *
     * @throws ASN1Exception if the next element is not a set
     */
    void startSet() throws ASN1Exception;

    /**
     * Advance to the end of a set. If there are any elements in the set that have
     * not yet been decoded, they will be discarded.
     *
     * @throws ASN1Exception if an error occurs while advancing to the end of the set
     */
    void endSet() throws ASN1Exception;

    /**
     * Starting decoding an ASN.1 "set of" element. All subsequent decode operations will
     * decode elements from this set until {@link #endSetOf()} is called.
     *
     * @throws ASN1Exception if the next element is not a set
     */
    void startSetOf() throws ASN1Exception;

    /**
     * Advance to the end of a "set of" element. If there are any elements in the set that
     * have not yet been decoded, they will be discarded.
     *
     * @throws ASN1Exception if an error occurs while advancing to the end of the set
     */
    void endSetOf() throws ASN1Exception;

    /**
     * Decode the next ASN.1 element as an octet string.
     *
     * @return the decoded octet string, as a byte array
     * @throws ASN1Exception if the next element is not an octet string
     */
    byte[] decodeOctetString() throws ASN1Exception;

    /**
     * Decode the next ASN.1 element as an octet string.
     *
     * @return the decoded octet string, as a UTF-8 string
     * @throws ASN1Exception if the next element is not an octet string
     */
    String decodeOctetStringAsString() throws ASN1Exception;

    /**
     * Decode the next ASN.1 element as an octet string.
     *
     * @param charSet the character set to use when decoding
     * @return the decoded octet string
     * @throws ASN1Exception if the next element is not an octet string
     */
    String decodeOctetStringAsString(String charSet) throws ASN1Exception;

    /**
     * Decode the next ASN.1 element as an IA5 string.
     *
     * @return the decoded IA5 string
     * @throws ASN1Exception if the next element is not an IA5 string
     */
    String decodeIA5String() throws ASN1Exception;

    /**
     * Decode the next ASN.1 element as an IA5 string.
     *
     * @param  the decoded IA5 string, as a byte array
     * @throws ASN1Exception if the next element is not an IA5 string
     */
    byte[] decodeIA5StringAsBytes() throws ASN1Exception;

    /**
     * Decode the next ASN.1 element as a bit string.
     *
     * @return the decoded bit string as a byte array, with any unused bits removed
     * @throws ASN1Exception if the next element is not a bit string
     */
    byte[] decodeBitString() throws ASN1Exception;

    /**
     * Decode the next ASN.1 element as a bit string.
     *
     * @return the decoded bit string as a binary string, with any unused bits removed
     * @throws ASN1Exception if the next element is not a bit string
     */
    String decodeBitStringAsString() throws ASN1Exception;

    /**
     * Decode the next ASN.1 element as an object identifier.
     *
     * @return the object identifier as a string
     * @throws ASN1Exception if the next element is not a bit string
     */
    String decodeObjectIdentifier() throws ASN1Exception;

    /**
     * Decode the next ASN.1 element as a null element.
     *
     * @throws ASN1Exception if the next element is not null
     */
    void decodeNull() throws ASN1Exception;

    /**
     * Indicate that the next ASN.1 element has the given implicit, context-specific tag.
     *
     * @param number the tag number for the implicit tag
     */
    void decodeImplicit(int number);

    /**
     * Indicate that the next ASN.1 element has the given implicit tag.
     *
     * @param clazz the class for the implicit tag
     * @param number the tag number for the implicit tag
     */
    void decodeImplicit(int clazz, int number);

    /**
     * Determine if the type of the next ASN.1 element matches the given type without
     * actually decoding the next element. This method can be used to determine if an
     * optional ASN.1 value has been included in the encoding or not.
     *
     * @param clazz the tag class to match against
     * @param number the tag number to match against
     * @param isConstructed whether or not the next element should be constructed
     * @return {@code true} if the type of the next ASN.1 element matches the given type
     * and {@code false} otherwise
     * @throws ASN1Exception if an error occurs while determining the type of the next element
     */
    boolean isNextType(int clazz, int number, boolean isConstructed) throws ASN1Exception;

    /**
     * Retrieve the type of the next ASN.1 element without actually decoding
     * the next element.
     *
     * @return the type of the next ASN.1 element
     * @throws ASN1Exception if an error occurs while determining the type of the next element
     */
    int peekType() throws ASN1Exception;

    /**
     * Skip over the next ASN.1 element.
     *
     * @throws ASN1Exception if the next element cannot be skipped
     */
    void skipElement() throws ASN1Exception;

    /**
     * Determine if there is at least one more ASN.1 element that can be read from the input stream.
     *
     * @return true if there is at least one more ASN.1 element that can be read and false otherwise
     */
    boolean hasNextElement();
}
