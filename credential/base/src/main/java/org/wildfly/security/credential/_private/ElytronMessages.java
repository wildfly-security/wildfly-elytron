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
    
    @Message(id = 2001, value = "Invalid key store entry password for alias \"%s\"")
    UnrecoverableKeyException invalidKeyStoreEntryPassword(String alias);
    
    @Message(id = 2002, value = "Invalid key store entry type for alias \"%s\" (expected %s, got %s)")
    KeyStoreException invalidKeyStoreEntryType(String alias, Class<?> expectedClass, Class<?> actualClass);
    
    @Message(id = 2003, value = "Key store key for alias \"%s\" cannot be protected")
    KeyStoreException keyCannotBeProtected(String alias);
    
    @Message(id = 2004, value = "Key store failed to translate password for alias \"%s\"")
    IOException keyStoreFailedToTranslate(String alias, @Cause Throwable cause);
    
    @Message(id = 2005, value = "Key store failed to identify a suitable algorithm for alias \"%s\"")
    NoSuchAlgorithmException noAlgorithmForPassword(String alias);
    
    @Message(id = 2006, value = "Unexpected whitespace in password file")
    IOException unexpectedWhitespaceInPasswordFile();
    
    @Message(id = 2007, value = "Unexpected end of file")
    EOFException unexpectedEof();
    
    @Message(id = 2008, value = "A reversible load is not possible until the KeyStore has first been initialized")
    IllegalStateException reversibleLoadNotPossible();
    
    @Message(id = 2009, value = "Unable to create a new KeyStore instance")
    IOException unableToCreateKeyStore(@Cause Exception cause);
    
    @Message(id = 2012, value = "An empty alias filter was supplied")
    IllegalArgumentException emptyFilter();
    
    @Message(id = 2013, value = "Filter is missing '+' or '-' at offset %d")
    IllegalArgumentException missingPlusMinusAt(long position);
    
    @Message(id = 2014, value = "Invalid first word '%s', must be one of ALL/NONE")
    IllegalArgumentException invalidFirstWord(String firstWord);
    
    @Message(id = 2015, value = "Failed to obtain DirContext")
    IllegalStateException failedToObtainDirContext(@Cause Throwable cause);
    
    @Message(id = 2016, value = "Failed to return DirContext")
    IllegalStateException failedToReturnDirContext(@Cause Throwable cause);
    
    @Message(id = 2017, value = "LdapKeyStore failed to obtain alias [%s]")
    IllegalStateException ldapKeyStoreFailedToObtainAlias(String alias, @Cause Throwable cause);
    
    @Message(id = 2018, value = "LdapKeyStore failed to obtain certificate [%s]")
    IllegalStateException ldapKeyStoreFailedToObtainCertificate(String alias, @Cause Throwable cause);
    
    @Message(id = 2019, value = "LdapKeyStore failed to obtain certificate chain [%s]")
    IllegalStateException ldapKeyStoreFailedToObtainCertificateChain(String alias, @Cause Throwable cause);
    
    @Message(id = 2020, value = "LdapKeyStore failed to recover key of alias [%s]")
    IllegalStateException ldapKeyStoreFailedToObtainKey(String alias, @Cause Throwable cause);
    
    @Message(id = 2021, value = "LdapKeyStore failed to obtain alias by certificate")
    IllegalStateException ldapKeyStoreFailedToObtainAliasByCertificate(@Cause Throwable cause);
    
    @Message(id = 2022, value = "LdapKeyStore failed to recover key of alias [%s]")
    UnrecoverableKeyException ldapKeyStoreFailedToRecoverKey(String alias, @Cause Throwable cause);
    
    @Message(id = 2023, value = "LdapKeyStore failed to obtain creation date of alias [%s]")
    IllegalStateException ldapKeyStoreFailedToObtainCreationDate(String alias, @Cause Throwable cause);
    
    @Message(id = 2024, value = "Alias [%s] does not exist in LdapKeyStore and not configured for creation")
    KeyStoreException creationNotConfigured(String alias);
    
    @Message(id = 2025, value = "LdapKeyStore failed store alias [%s]")
    KeyStoreException ldapKeyStoreFailedToStore(String alias, @Cause Throwable cause);
    
    @Message(id = 2026, value = "LdapKeyStore failed to serialize certificate of alias [%s]")
    KeyStoreException ldapKeyStoreFailedToSerializeCertificate(String alias, @Cause Throwable cause);
    
    @Message(id = 2027, value = "LdapKeyStore failed to protect (pack into keystore) key of alias [%s]")
    KeyStoreException ldapKeyStoreFailedToSerializeKey(String alias, @Cause Throwable cause);
    
    @Message(id = 2028, value = "LdapKeyStore failed to delete alias [%s]")
    KeyStoreException ldapKeyStoreFailedToDelete(String alias, @Cause Throwable cause);
    
    @Message(id = 2029, value = "LdapKeyStore failed to delete alias [%s] - alias not found")
    KeyStoreException ldapKeyStoreFailedToDeleteNonExisting(String alias);
    
    @Message(id = 2030, value = "LdapKeyStore failed to test alias [%s] existence")
    IllegalStateException ldapKeyStoreFailedToTestAliasExistence(String alias, @Cause Throwable cause);
    
    @Message(id = 2031, value = "LdapKeyStore failed to iterate aliases")
    IllegalStateException ldapKeyStoreFailedToIterateAliases(@Cause Throwable cause);
    
    @Message(id = 2032, value = "keySpec must be SecretKeySpect, given: [%s]")
    InvalidKeySpecException keySpecMustBeSecretKeySpec(String type);
    
    @Message(id = 2033, value = "key must implement SecretKeySpec and keySpec must be SecretKeySpec, given key, keySpec: [%s]")
    InvalidKeySpecException keyMustImplementSecretKeySpecAndKeySpecMustBeSecretKeySpec(String keyAndKeySpec);

    @Message(id = 2035, value = "KeyStore type could not be detected")
    KeyStoreException keyStoreTypeNotDetected();
    
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
