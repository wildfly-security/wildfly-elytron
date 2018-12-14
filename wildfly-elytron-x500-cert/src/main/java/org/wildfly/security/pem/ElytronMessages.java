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

package org.wildfly.security.pem;

import java.security.cert.CertificateException;

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
}

