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

import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.InvalidObjectException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Permission;
import java.security.Principal;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.NoSuchElementException;

import static org.jboss.logging.Logger.Level.DEBUG;
import static org.jboss.logging.Logger.Level.ERROR;
import static org.jboss.logging.Logger.Level.WARN;

import javax.naming.NamingException;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import javax.security.auth.login.LoginException;
import javax.security.sasl.SaslException;
import javax.xml.namespace.QName;
import javax.xml.stream.Location;
import javax.xml.stream.XMLStreamReader;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.Param;
import org.wildfly.security._private.ElytronMessages;


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
    
    @Message(id = 1059, value = "Public and private key algorithm names are mismatched")
    IllegalArgumentException mismatchedPublicPrivateKeyAlgorithms();
    
    @Message(id = 1061, value = "Public key is null")
    IllegalArgumentException publicKeyIsNull();
    
    @Message(id = 1063, value = "Private key is null")
    IllegalArgumentException privateKeyIsNull();
    
    // Also used in SASL / OTP
    @Message(id = 5151, value = "Invalid OTP algorithm \"%s\"")
    SaslException mechInvalidOTPAlgorithm(String algorithm);
    
    @Message(id = 8001, value = "Unrecognized key spec algorithm")
    InvalidKeySpecException invalidKeySpecUnrecognizedKeySpecAlgorithm();
    
    @Message(id = 8002, value = "Password spec cannot be rendered as a string")
    InvalidKeySpecException invalidKeySpecPasswordSpecCannotBeRenderedAsString();
    
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
    
    @Message(id = 8022, value = "BSD DES crypt password hash must be %d bytes")
    InvalidKeySpecException invalidKeySpecBsdDesCryptPasswordHashMustBeBytes(int bytes);

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
