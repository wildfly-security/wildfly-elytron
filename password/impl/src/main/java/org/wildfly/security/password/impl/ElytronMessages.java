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

package org.wildfly.security.password.impl;

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
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 2, value = "Parameter %s is empty")
    IllegalArgumentException emptyParameter(String parameter);

    @Message(id = 4, value = "Unrecognized algorithm \"%s\"")
    IllegalArgumentException unrecognizedAlgorithm(String algorithm);

    @Message(id = 5151, value = "Invalid OTP algorithm \"%s\"")
    SaslException mechInvalidOTPAlgorithm(String algorithm);

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

    @Message(id = 8026, value = "Unknown algorithm \"%s\" or incompatible PasswordSpec \"%s\"")
    InvalidKeySpecException invalidKeySpecUnknownAlgorithmOrIncompatiblePasswordSpec(String algorithm, String passwordSpec);

    @Message(id = 8027, value = "Unknown password type or algorithm")
    InvalidKeyException invalidKeyUnknownUnknownPasswordTypeOrAlgorithm();

    @Message(id = 8028, value = "Invalid algorithm \"%s\"")
    NoSuchAlgorithmException noSuchAlgorithmInvalidAlgorithm(String algorithm);

}
