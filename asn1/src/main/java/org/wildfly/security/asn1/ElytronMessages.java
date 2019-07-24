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

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;


/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 12, max = 12),
    @ValidIdRange(min = 7004, max = 7024)
})
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 12, value = "Unable to load OIDs database from properties file")
    IllegalStateException unableToLoadOidsFromPropertiesFile(@Cause Throwable cause);

    @Message(id = 7004, value = "Unexpected ASN.1 tag encountered")
    ASN1Exception asnUnexpectedTag();

    @Message(id = 7005, value = "Unable to read X.509 certificate data")
    ASN1Exception asnUnableToReadCertificateData(@Cause Throwable cause);

    @Message(id = 7009, value = "No sequence to end")
    IllegalStateException noSequenceToEnd();

    @Message(id = 7010, value = "No set to end")
    IllegalStateException noSetToEnd();

    @Message(id = 7011, value = "No explicitly tagged element to end")
    IllegalStateException noExplicitlyTaggedElementToEnd();

    @Message(id = 7012, value = "Unexpected end of input")
    ASN1Exception asnUnexpectedEndOfInput();

    @Message(id = 7013, value = "Invalid number of unused bits")
    ASN1Exception asnInvalidNumberOfUnusedBits();

    @Message(id = 7014, value = "Non-zero length encountered for null type tag")
    ASN1Exception asnNonZeroLengthForNullTypeTag();

    @Message(id = 7015, value = "Invalid high-tag-number form")
    ASN1Exception asnInvalidHighTagNumberForm();

    @Message(id = 7016, value = "Length encoding exceeds 4 bytes")
    ASN1Exception asnLengthEncodingExceeds4bytes();

    @Message(id = 7017, value = "Invalid OID character")
    ASN1Exception asnInvalidOidCharacter();

    @Message(id = 7018, value = "OID must have at least 2 components")
    ASN1Exception asnOidMustHaveAtLeast2Components();

    @Message(id = 7019, value = "Invalid value for first OID component; expected 0, 1, or 2")
    ASN1Exception asnInvalidValueForFirstOidComponent();

    @Message(id = 7020, value = "Invalid value for second OID component; expected a value between 0 and 39 (inclusive)")
    ASN1Exception asnInvalidValueForSecondOidComponent();

    @Message(id = 7021, value = "Invalid length")
    ASN1Exception asnInvalidLength();

    @Message(id = 7022, value = "Unknown tag type: %d")
    ASN1Exception asnUnknownTagType(int type);

    @Message(id = 7023, value = "Unexpected character byte for printable string")
    ASN1Exception asnUnexpectedCharacterByteForPrintableString();

    @Message(id = 7024, value = "Invalid length encountered for boolean type tag")
    ASN1Exception asnInvalidLengthForBooleanTypeTag();

}
