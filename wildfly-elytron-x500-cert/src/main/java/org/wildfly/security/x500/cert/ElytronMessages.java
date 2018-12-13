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

package org.wildfly.security.x500.cert;

import java.security.cert.CertificateException;
import java.time.ZonedDateTime;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.wildfly.security.asn1.ASN1Exception;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 3010, value = "Malformed PEM content at offset %d")
    IllegalArgumentException malformedPemContent(long offset);

    @Message(id = 3011, value = "Invalid PEM type (expected \"%s\", got \"%s\"")
    IllegalArgumentException invalidPemType(String expected, String actual);

    @Message(id = 3012, value = "Certificate parse error")
    IllegalArgumentException certificateParseError(@Cause CertificateException cause);

    @Message(id = 3023, value = "PublicKey parse error")
    IllegalArgumentException publicKeyParseError(@Cause Throwable cause);

    @Message(id = 3033, value = "PrivateKey parse error")
    IllegalArgumentException privateKeyParseError(@Cause Throwable cause);

    @Message(id = 7001, value = "Unrecognized encoding algorithm [%s]")
    ASN1Exception asnUnrecognisedAlgorithm(String algorithm);

    @Message(id = 7004, value = "Unexpected ASN.1 tag encountered")
    ASN1Exception asnUnexpectedTag();

    @Message(id = 10000, value = "X.509 certificate extension with OID %s already exists")
    IllegalArgumentException extensionAlreadyExists(String oid);

    @Message(id = 10001, value = "No signature algorithm name given")
    IllegalArgumentException noSignatureAlgorithmNameGiven();

    @Message(id = 10002, value = "Signature algorithm name \"%s\" is not recognized")
    IllegalArgumentException unknownSignatureAlgorithmName(String signatureAlgorithmName);

    @Message(id = 10003, value = "No signing key given")
    IllegalArgumentException noSigningKeyGiven();

    @Message(id = 10004, value = "Signing key algorithm name \"%s\" is not compatible with signature algorithm name \"%s\"")
    IllegalArgumentException signingKeyNotCompatWithSig(String signingKeyAlgorithm, String signatureAlgorithmName);

    @Message(id = 10005, value = "Not-valid-before date of %s is after not-valid-after date of %s")
    IllegalArgumentException validAfterBeforeValidBefore(ZonedDateTime notValidBefore, ZonedDateTime notValidAfter);

    @Message(id = 10006, value = "No issuer DN given")
    IllegalArgumentException noIssuerDnGiven();

    @Message(id = 10007, value = "No public key given")
    IllegalArgumentException noPublicKeyGiven();

    @Message(id = 10008, value = "Issuer and subject unique ID are only allowed in certificates with version 2 or higher")
    IllegalArgumentException uniqueIdNotAllowed();

    @Message(id = 10009, value = "Extensions are only allowed in certificates with version 3 or higher")
    IllegalArgumentException extensionsNotAllowed();

    @Message(id = 10010, value = "X.509 encoding of public key with algorithm \"%s\" failed")
    IllegalArgumentException invalidKeyForCert(String publicKeyAlgorithm, @Cause Exception cause);

    @Message(id = 10011, value = "Failed to sign certificate")
    IllegalArgumentException certSigningFailed(@Cause Exception cause);

    @Message(id = 10012, value = "Certificate serial number must be positive")
    IllegalArgumentException serialNumberTooSmall();

    @Message(id = 10013, value = "Certificate serial number too large (cannot exceed 20 octets)")
    IllegalArgumentException serialNumberTooLarge();

    @Message(id = 10014, value = "Failed to sign certification request info")
    IllegalArgumentException certRequestInfoSigningFailed(@Cause Exception cause);

    @Message(id = 10015, value = "No certificate given")
    IllegalArgumentException noCertificateGiven();

    @Message(id = 10017, value = "No DN given")
    IllegalArgumentException noDnGiven();

    @Message(id = 10018, value = "Failed to generate self-signed X.509 certificate")
    IllegalArgumentException selfSignedCertificateGenerationFailed(@Cause Exception cause);

    @Message(id = 10019, value = "Unable to determine default compatible signature algorithm name for key algorithm name \"%s\"")
    IllegalArgumentException unableToDetermineDefaultCompatibleSignatureAlgorithmName(String keyAlgorithmName);

    @Message(id = 10020, value = "Creating an X.509 certificate extension from a string value is not supported for extension name \"%s\"")
    IllegalArgumentException certificateExtensionCreationFromStringNotSupported(String extensionName);

    @Message(id = 10021, value = "Invalid X.509 certificate extension string value \"%s\"")
    IllegalArgumentException invalidCertificateExtensionStringValue(String extensionValue);

    @Message(id = 10022, value = "Failed to create X.509 certificate extension from string value")
    IllegalArgumentException certificateExtensionCreationFromStringFailed(@Cause Exception cause);

    @Message(id = 10023, value = "X.509 certificate extension \"%s\" must be non-critical")
    IllegalArgumentException certificateExtensionMustBeNonCritical(String extensionName);

    @Message(id = 10024, value = "Invalid X.509 certificate extension string value")
    IllegalArgumentException invalidCertificateExtensionStringValue();
}

