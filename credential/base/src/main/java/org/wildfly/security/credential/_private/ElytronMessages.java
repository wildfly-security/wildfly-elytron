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

package org.wildfly.security.credential._private;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.security.sasl.SaslException;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages tls = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.tls");

    @Message(id = 2, value = "Parameter %s is empty")
    IllegalArgumentException emptyParameter(String parameter);

    @Message(id = 4, value = "Unrecognized algorithm \"%s\"")
    IllegalArgumentException unrecognizedAlgorithm(String algorithm);

    @Message(id = 1037, value = "Certificate chain is empty")
    IllegalArgumentException certificateChainIsEmpty();

    @Message(id = 1053, value = "Insufficient data to form a digest and a salt")
    InvalidKeySpecException insufficientDataToFormDigestAndSalt();

    @Message(id = 1054, value = "Invalid salt \"%s%s\"")
    IllegalArgumentException invalidSalt(char lo, char hi);

    @Message(id = 1055, value = "Invalid rounds \"%s%s%s%s\"")
    IllegalArgumentException invalidRounds(char b0, char b1, char b2, char b3);

    @Message(id = 1056, value = "Invalid salt \"%s%s%s%s\"")
    IllegalArgumentException invalidSalt(char b0, char b1, char b2, char b3);

    @Message(id = 1059, value = "Public and private key algorithm names are mismatched")
    IllegalArgumentException mismatchedPublicPrivateKeyAlgorithms();

    @Message(id = 1061, value = "Public key is null")
    IllegalArgumentException publicKeyIsNull();

    @Message(id = 1063, value = "Private key is null")
    IllegalArgumentException privateKeyIsNull();

    @Message(id = 2032, value = "keySpec must be SecretKeySpect, given: [%s]")
    InvalidKeySpecException keySpecMustBeSecretKeySpec(String type);

    @Message(id = 2033, value = "key must implement SecretKeySpec and keySpec must be SecretKeySpec, given key, keySpec: [%s]")
    InvalidKeySpecException keyMustImplementSecretKeySpecAndKeySpecMustBeSecretKeySpec(String keyAndKeySpec);

    // Also used in SASL / OTP
    @Message(id = 5151, value = "Invalid OTP algorithm \"%s\"")
    SaslException mechInvalidOTPAlgorithm(String algorithm);

    @Message(id = 8001, value = "Unrecognized key spec algorithm")
    InvalidKeySpecException invalidKeySpecUnrecognizedKeySpecAlgorithm();

    @Message(id = 8002, value = "Password spec cannot be rendered as a string")
    InvalidKeySpecException invalidKeySpecPasswordSpecCannotBeRenderedAsString();

    @Message(id = 8003, value = "Unknown crypt string algorithm")
    InvalidKeySpecException invalidKeySpecUnknownCryptStringAlgorithm();

    @Message(id = 8004, value = "Invalid character encountered")
    InvalidKeySpecException invalidKeySpecInvalidCharacterEncountered();

    @Message(id = 8005, value = "No iteration count terminator given")
    InvalidKeySpecException invalidKeySpecNoIterationCountTerminatorGiven();

    @Message(id = 8006, value = "Unexpected end of input string")
    InvalidKeySpecException invalidKeySpecUnexpectedEndOfInputString();

    @Message(id = 8007, value = "No salt terminator given")
    InvalidKeySpecException invalidKeySpecNoSaltTerminatorGiven();

    @Message(id = 8008, value = "Invalid hash length")
    IllegalArgumentException invalidHashLength();

    @Message(id = 8009, value = "Unexpected end of password string")
    InvalidKeySpecException invalidKeySpecUnexpectedEndOfPasswordString();

    @Message(id = 8010, value = "Unexpected end of password string")
    InvalidKeySpecException invalidKeySpecUnexpectedEndOfPasswordStringWithCause(@Cause Throwable cause);

    @Message(id = 8011, value = "Invalid minor version")
    InvalidKeySpecException invalidKeySpecInvalidMinorVersion();

    @Message(id = 8012, value = "Invalid cost: must be a two digit integer")
    InvalidKeySpecException invalidKeySpecCostMustBeTwoDigitInteger();

    @Message(id = 8013, value = "No such MessageDigest algorithm for \"%s\"")
    InvalidKeySpecException invalidKeySpecNoSuchMessageDigestAlgorithm(String algorithm);

    @Message(id = 8014, value = "No such MessageDigest algorithm for \"%s\"")
    InvalidKeyException invalidKeyNoSuchMessageDigestAlgorithm(String algorithm);

    @Message(id = 8015, value = "Cannot verify password")
    InvalidKeyException invalidKeyCannotVerifyPassword(@Cause Throwable cause);

    @Message(id = 8017, value = "DES crypt password hash must be %d bytes")
    InvalidKeyException invalidKeyDesCryptPasswordHashMustBeBytes(int bytes);

    @Message(id = 8018, value = "Salt must be %d bytes (%d bits)")
    InvalidParameterSpecException invalidParameterSpecSaltMustBeBytesBits(int bytes, int bits);

    @Message(id = 8020, value = "Invalid number of rounds. Must be an integer between %d and %d, inclusive")
    IllegalArgumentException invalidNumberOfRoundsMustBeIntBetween(int min, int max);

    @Message(id = 8021, value = "Invalid salt: must be %d bytes long")
    IllegalArgumentException invalidSaltMustBeBytesLong(int length);

    @Message(id = 8022, value = "BSD DES crypt password hash must be %d bytes")
    InvalidKeySpecException invalidKeySpecBsdDesCryptPasswordHashMustBeBytes(int bytes);

    @Message(id = 8023, value = "Salt must be %d bytes")
    InvalidParameterSpecException invalidParameterSpecSaltMustBeBytes(int bytes);

    @Message(id = 8024, value = "BSD DES crypt password hash must be %d bytes")
    InvalidKeyException invalidKeyBsdDesCryptPasswordHashMustBeBytes(int bytes);

    @Message(id = 8025, value = "Expected to get a \"%s\" as spec, got \"%s\"")
    InvalidKeySpecException invalidKeySpecExpectedSpecGotSpec(String expected, String got);

    @Message(id = 8026, value = "Unknown algorithm or incompatible PasswordSpec")
    InvalidKeySpecException invalidKeySpecUnknownAlgorithmOrIncompatiblePasswordSpec();

    @Message(id = 8027, value = "Unknown password type or algorithm")
    InvalidKeyException invalidKeyUnknownUnknownPasswordTypeOrAlgorithm();

    @Message(id = 8028, value = "Invalid algorithm \"%s\"")
    NoSuchAlgorithmException noSuchAlgorithmInvalidAlgorithm(String algorithm);

    @Message(id = 8029, value = "Could not obtain key spec encoding identifier.")
    IllegalArgumentException couldNotObtainKeySpecEncodingIdentifier();

    @Message(id = 9000, value = "Public and private key parameters are mismatched")
    IllegalArgumentException mismatchedPublicPrivateKeyParameters();


}
