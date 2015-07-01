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

package org.wildfly.security._private;

import java.io.EOFException;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import javax.security.auth.callback.Callback;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServerFactory;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.Param;
import org.jboss.modules.ModuleIdentifier;
import org.jboss.modules.ModuleLoadException;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.auth.callback.FastUnsupportedCallbackException;
import org.wildfly.security.auth.spi.RealmUnavailableException;
import org.wildfly.security.util.DecodeException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages xmlLog = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.xml");

    @LogMessage
    @Message(id = 1, value = "WildFly Elytron version %s")
    void logVersion(String versionString);

    @Message(id = 2, value = "Parse error")
    String parseError();

    @Message(id = 3, value = "No algorithm found matching TLS/SSL protocol selection criteria")
    NoSuchAlgorithmException noAlgorithmForSslProtocol();

    @Message(id = 4, value = "Empty certificate chain is not trusted")
    CertificateException emptyChainNotTrusted();

    @Message(id = 5, value = "Certificate not trusted due to realm failure for principal %s")
    CertificateException notTrustedRealmProblem(@Cause RealmUnavailableException e, Principal principal);

    @Message(id = 6, value = "Credential validation failed; certificate is not trusted for principal %s")
    CertificateException notTrusted(Principal principal);

    @Message(id = 7, value = "No module found for identifier \"%s\"")
    ConfigXMLParseException noModuleFound(@Param XMLStreamReader reader, @Cause ModuleLoadException e, ModuleIdentifier id);

    @Message(id = 8, value = "Invalid port number \"%s\" specified for attribute \"%s\" of element \"%s\"; expected a numerical value between 1 and 65535 (inclusive)")
    ConfigXMLParseException xmlInvalidPortNumber(@Param XMLStreamReader reader, String attributeValue, String attributeName, QName elementName);

    @Message(id = 9, value = "No authentication is in progress")
    IllegalStateException noAuthenticationInProgress();

    @Message(id = 10, value = "No successful authentication on this context")
    IllegalStateException noSuccessfulAuthentication();

    @Message(id = 11, value = "Authentication already initiated on this context")
    IllegalStateException alreadyInitiated();

    @Message(id = 12, value = "Realm map does not contain mapping for default realm '%s'")
    IllegalArgumentException realmMapDoesntContainDefault(String defaultRealm);

    @Message(id = 13, value = "This builder has already been built")
    IllegalStateException builderAlreadyBuilt();

    @Message(id = 14, value = "Invalid key store entry password for alias \"%s\"")
    UnrecoverableKeyException invalidKeyStoreEntryPassword(String alias);

    @Message(id = 15, value = "Invalid key store entry type for alias \"%s\" (expected %s, got %s)")
    KeyStoreException invalidKeyStoreEntryType(String alias, Class<?> expectedClass, Class<?> actualClass);

    @Message(id = 16, value = "Key store key for alias \"%s\" cannot be protected")
    KeyStoreException keyCannotBeProtected(String alias);

    @Message(id = 17, value = "Key store failed to translate password for alias \"%s\"")
    IOException keyStoreFailedToTranslate(String alias, @Cause Throwable cause);

    @Message(id = 18, value = "Key store failed to identify a suitable algorithm for alias \"%s\"")
    NoSuchAlgorithmException noAlgorithmForPassword(String alias);

    @Message(id = 19, value = "Unexpected whitespace in password file")
    IOException unexpectedWhitespaceInPasswordFile();

    @Message(id = 20, value = "Unexpected end of file")
    EOFException unexpectedEof();

    @Message(id = 21, value = "[%s] SASL exchange received a message after authentication was already complete")
    SaslException saslMessageAfterComplete(String mechName);

    @Message(id = 22, value = "[%s] SASL user name contains an invalid or disallowed character")
    SaslException saslUserNameContainsInvalidCharacter(String mechName);

    @Message(id = 23, value = "[%s] SASL user name could not be decoded from encoding \"%s\"")
    SaslException saslUserNameDecodeFailed(String mechName, String encodingName);

    @Message(id = 24, value = "[%s] SASL authorization failed")
    SaslException saslAuthorizationFailed(String mechName, @Cause Throwable cause);

    @Message(id = 25, value = "[%s] SASL authentication is not yet complete")
    IllegalStateException saslAuthenticationNotComplete(String mechName);

    @Message(id = 26, value = "[%s] SASL mechanism not support security layer (wrapping/unwrapping)")
    SaslException saslNoSecurityLayer(String mechName);

    @Message(id = 27, value = "[%s] Invalid SASL negotiation message received")
    SaslException saslInvalidMessageReceived(String mechName);

    @Message(id = 28, value = "[%s] No SASL login name was given")
    SaslException saslNoLoginNameGiven(String mechName);

    @Message(id = 29, value = "[%s] No SASL password was given")
    SaslException saslNoPasswordGiven(String mechName);

    @Message(id = 30, value = "[%s] SASL authentication failed due to one or more malformed fields")
    SaslException saslMalformedFields(String mechName, @Cause IllegalArgumentException ex);

    @Message(id = 31, value = "[%s] SASL message is too long")
    SaslException saslMessageTooLong(String mechName);

    @Message(id = 32, value = "[%s] SASL server-side authentication failed")
    SaslException saslServerSideAuthenticationFailed(String mechName, @Cause Exception e);

    @Message(id = 33, value = "[%s] SASL password not verified")
    SaslException saslPasswordNotVerified(String mechName);

    @Message(id = 34, value = "[%s] SASL authorization failed: \"%s\" is not authorized to act on behalf of \"%s\"")
    SaslException saslAuthorizationFailed(String mechName, String userName, String authorizationId);

    @Message(id = 35, value = "Unexpected character U+%04x at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnexpectedChar(int codePoint, int offset, String string);

    @Message(id = 36, value = "Unrecognized token \"%s\" in mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnknownToken(String word, String string);

    @Message(id = 37, value = "Token \"%s\" not allowed at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorTokenNotAllowed(String token, int offset, String string);

    @Message(id = 38, value = "Expected token \"%s\" at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorTokenExpected(String token, int offset, String string);

    @Message(id = 39, value = "[%s] Proxied SASL authentication failed")
    SaslException saslProxyAuthenticationFailed(String mechName);

    @Message(id = 40, value = "No SASL client mechanism \"%s\" is available with the current configuration from %s")
    SaslException saslNoClientMechanism(String mechName, SaslClientFactory clientFactory);

    @Message(id = 41, value = "No SASL server mechanism \"%s\" is available with the current configuration from %s")
    SaslException saslNoServerMechanism(String mechName, SaslServerFactory serverFactory);

    @Message(id = 42, value = "A revertible load is not possible until the KeyStore has first been initialised")
    IllegalStateException revertibleLoadNotPossible();

    @Message(id = 43, value = "Unable to create a new KeyStore instance")
    IOException unableToCreateKeyStore(@Cause Exception cause);

    @Message(id = 44, value = "Invalid password type for alias %s (expected %s, got %s)")
    KeyStoreException invalidPasswordType(String alias, Class<?> expectedClass, Class<?> actualClass);

    @Message(id = 45, value = "The password entry must contain a non null realm name")
    KeyStoreException invalidNullRealmInPasswordEntry();

    @Message(id = 46, value = "The password entry realm for alias %s must match the properties-based keystore realm. (expected %s, got %s)")
    KeyStoreException invalidRealmNameInPasswordEntry(String alias, String keyStoreRealm, String actualRealm);

    @Message(id = 47, value = "Invalid algorithm found in password entry for alias %s (expected %s, got %s)")
    KeyStoreException invalidAlgorithmInPasswordEntry(String alias, String expectedAlgorithm, String actualAlgorithm);

    @Message(id = 48, value = "No realm name found in properties file")
    IOException noRealmFoundInProperties();

    @Message(id = 49, value = "Unexpected padding")
    DecodeException unexpectedPadding();

    @Message(id = 50, value = "Expected padding")
    DecodeException expectedPadding();

    @Message(id = 51, value = "Incomplete decode")
    DecodeException incompleteDecode();

    @Message(id = 52, value = "Expected %d padding characters")
    DecodeException expectedPaddingCharacters(int numExpected);

    @Message(id = 53, value = "Invalid base 32 character")
    DecodeException invalidBase32Character();

    @Message(id = 54, value = "Expected an even number of hex characters")
    DecodeException expectedEvenNumberOfHexCharacters();

    @Message(id = 55, value = "Invalid hex character")
    DecodeException invalidHexCharacter();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 56, value = "JAAS authentication failed for principal %s")
    void debugJAASAuthenticationFailure(Principal principal, @Cause Throwable cause);

    @Message(id = 57, value = "Invalid principal type (expected %s, got %s)")
    IllegalArgumentException invalidPrincipalType(Class<?> expectedType, Class<?> actualType);

    @Message(id = 58, value = "Failed to create login context")
    RealmUnavailableException failedToCreateLoginContext(@Cause Throwable cause);

    @Message(id = 59, value = "Failed to instantiate custom CallbackHandler")
    RealmUnavailableException failedToInstantiateCustomHandler(@Cause Throwable cause);

    // 60

    @Message(id = 61, value = "Credential cannot be converted to a password")
    FastUnsupportedCallbackException failedToConvertCredentialToPassword(@Param Callback callback);

    @Message(id = 62, value = "[%s] Initial challenge must be empty")
    SaslException saslInitialChallengeMustBeEmpty(String mechName);

    @Message(id = 63, value = "[%s] Unable to set channel binding")
    SaslException saslUnableToSetChannelBinding(String mechName, @Cause Exception e);

    @Message(id = 64, value = "Failed to determine channel binding status")
    SaslException saslFailedToDetermineChannelBindingStatus(@Cause Exception e);

    @Message(id = 65, value = "[%s] Mutual authentication not enabled")
    SaslException saslMutualAuthenticationNotEnabled(String mechName);

    @Message(id = 66, value = "[%s] Unable to map SASL mechanism name to a GSS-API OID")
    SaslException saslMechanismToOidMappingFailed(String mechName, @Cause Exception e);

    @Message(id = 67, value = "[%s] Unable to dispose of GSSContext")
    SaslException saslUnableToDisposeGssContext(String mechName, @Cause Exception e);

    @Message(id = 68, value = "[%s] Unable to create name for acceptor")
    SaslException saslUnableToCreateNameForAcceptor(String mechName, @Cause Exception e);

    @Message(id = 69, value = "[%s] Unable to create GSSContext")
    SaslException saslUnableToCreateGssContext(String mechName, @Cause Exception e);

    @Message(id = 70, value = "[%s] Unable to set GSSContext request flags")
    SaslException saslUnableToSetGssContextRequestFlags(String mechName, @Cause Exception e);

    @Message(id = 71, value = "[%s] Unable to accept SASL client message")
    SaslException saslUnableToAcceptClientMessage(String mechName, @Cause Exception e);

    @Message(id = 72, value = "[%s] GSS-API mechanism mismatch between SASL client and server")
    SaslException saslGssApiMechanismMismatch(String mechName);

    @Message(id = 73, value = "[%s] Channel binding not supported for this SASL mechanism")
    SaslException saslChannelBindingNotSupported(String mechName);

    @Message(id = 74, value = "[%s] Channel binding type mismatch between SASL client and server")
    SaslException saslChannelBindingTypeMismatch(String mechName);

    @Message(id = 75, value = "[%s] Channel binding not provided by client")
    SaslException saslChannelBindingNotProvided(String mechName);

    @Message(id = 76, value = "[%s] Unable to determine peer name")
    SaslException saslUnableToDeterminePeerName(String mechName, @Cause Exception e);

    @Message(id = 77, value = "[%s] SASL client refuses to initiate authentication")
    SaslException saslClientRefusesToInitiateAuthentication(String mechName);

    // 78

    // 79

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 80, value = "[%s] JAAS logout failed for principal %s")
    void debugJAASLogoutFailure(String mechName, Principal principal, @Cause Throwable cause);

    @Message(id = 81, value = "No default trust manager available")
    NoSuchAlgorithmException noDefaultTrustManager();

    @Message(id = 82, value = "No host for SSL connection")
    SSLHandshakeException noHostForSslConnection();

    @Message(id = 83, value = "SSL channel is closed")
    SSLException sslClosed();

    @Message(id = 84, value = "Initial SSL/TLS data is not a handshake record")
    SSLHandshakeException notHandshakeRecord();

    @Message(id = 85, value = "Initial SSL/TLS handshake record is invalid")
    SSLHandshakeException invalidHandshakeRecord();

    @Message(id = 86, value = "Initial SSL/TLS handshake spans multiple records")
    SSLHandshakeException multiRecordSSLHandshake();

    @Message(id = 87, value = "Expected \"client hello\" record")
    SSLHandshakeException expectedClientHello();

    @Message(id = 88, value = "Unsupported SSL/TLS record")
    SSLHandshakeException unsupportedSslRecord();

    @Message(id = 89, value = "Invalid SNI extension")
    SSLProtocolException invalidSniExt();

    @Message(id = 90, value = "Not enough data in record to fill declared item size")
    SSLProtocolException notEnoughData();

    @Message(id = 91, value = "Empty host name in SNI record data")
    SSLProtocolException emptyHostNameSni();

    @Message(id = 92, value = "Duplicated SNI server name of type %d")
    SSLProtocolException duplicatedSniServerName(int type);

    @Message(id = 93, value = "Unrecognized principal type for %s")
    IllegalArgumentException unrecognizedPrincipalType(Principal principal);

    @Message(id = 94, value = "Filesystem-backed realm unexpectedly failed to open path \"%s\" for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmFailedToOpen(Path path, String finalName, @Cause IOException cause);

    @Message(id = 95, value = "Filesystem-backed realm unexpectedly failed to read path \"%s\" for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmFailedToRead(Path path, String finalName, @Cause Exception cause);

    @Message(id = 96, value = "Invalid empty name given")
    IllegalArgumentException invalidEmptyName();

    @Message(id = 97, value = "Filesystem-backed realm encountered invalid file content in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidContent(Path path, int lineNumber, String name);

    @Message(id = 98, value = "Filesystem-backed realm encountered missing required attribute \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmMissingAttribute(String attribute, Path path, int lineNumber, String name);

    @Message(id = 99, value = "Filesystem-backed realm encountered invalid password format \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidPasswordFormat(String format, Path path, int lineNumber, String name);

    @Message(id = 100, value = "Filesystem-backed realm failed to rename \"%s\" to \"%s\"")
    RealmUnavailableException fileSystemRealmRenameFailed(String name, String finalName, @Cause IOException e);

    @Message(id = 101, value = "Filesystem-backed realm failed to delete identity \"%s\"")
    RealmUnavailableException fileSystemRealmDeleteFailed(String name, @Cause IOException e);

    @Message(id = 102, value = "Filesystem-backed realm failed to find identity \"%s\"")
    RealmUnavailableException fileSystemRealmNotFound(String name);

    @Message(id = 103, value = "Filesystem-backed realm failed to write to file \"%s\" for identity \"%s\"")
    RealmUnavailableException fileSystemRealmFailedToWrite(Path tempPath, String name, @Cause Exception e);

    @Message(id = 104, value = "Filesystem-backed realm cannot create duplicate identity for identity \"%s\"")
    RealmUnavailableException fileSystemRealmAlreadyExists(String name, @Cause Throwable e);

    @Message(id = 105, value = "Filesystem-backed realm encountered invalid certificate format \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmCertificateReadError(String format, Path path, int lineNumber, String name);

    @Message(id = 106, value = "Filesystem-backed realm encountered invalid key format \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmUnsupportedKeyFormat(String format, Path path, int lineNumber, String name);

    @Message(id = 107, value = "Filesystem-backed realm encountered invalid key algorithm for format \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmUnsupportedKeyAlgorithm(String format, Path path, int lineNumber, String name);

    @Message(id = 108, value = "[%s] Nonces do not match")
    SaslException saslNoncesDoNotMatch(String mechName);

    @Message(id = 109, value = "[%s] Server nonce is too short")
    SaslException saslServerNonceIsTooShort(String mechName);

    @Message(id = 110, value = "[%s] Iteration count %d is below the minimum of %d")
    SaslException saslIterationCountIsTooLow(String mechName, int iterationCount, int minimumIterationCount);

    @Message(id = 111, value = "[%s] Iteration count %d is above the maximum of %d")
    SaslException saslIterationCountIsTooHigh(String mechName, int iterationCount, int maximumIterationCount);

    @Message(id = 112, value = "[%s] Extensions unsupported")
    SaslException saslExtensionsUnsupported(String mechName);

    @Message(id = 113, value = "[%s] Invalid server message")
    SaslException saslInvalidServerMessage(String mechName);

    @Message(id = 114, value = "[%s] Invalid server message")
    SaslException saslInvalidServerMessageWithCause(String mechName, @Cause Throwable cause);

    @Message(id = 115, value = "[%s] Invalid client message")
    SaslException saslInvalidClientMessage(String mechName);

    @Message(id = 116, value = "[%s] Invalid client message")
    SaslException saslInvalidClientMessageWithCause(String mechName, @Cause Throwable cause);

    @Message(id = 117, value = "[%s] Server rejected authentication: %s")
    SaslException saslServerRejectedAuthentication(String mechName, String message);

    @Message(id = 118, value = "[%s] Server rejected authentication")
    SaslException saslServerRejectedAuthentication(String mechName);

    @Message(id = 119, value = "[%s] Server authenticity cannot be verified")
    SaslException saslServerAuthenticityCannotBeVerified(String mechName);

    @Message(id = 120, value = "[%s] Callback handler does not support user name")
    SaslException saslCallbackHandlerDoesNotSupportUserName(String mechName, @Cause Throwable cause);

    @Message(id = 121, value = "[%s] Callback handler does not support credential acquisition")
    SaslException saslCallbackHandlerDoesNotSupportCredentialAcquisition(String mechName, @Cause Throwable cause);

    @Message(id = 122, value = "[%s] Callback handler does not support authorization")
    SaslException saslAuthorizationUnsupported(String mechName, @Cause Throwable cause);

    @Message(id = 123, value = "[%s] Callback handler failed for unknown reason")
    SaslException saslCallbackHandlerFailedForUnknownReason(String mechName, @Cause Throwable cause);

    @Message(id = 124, value = "[%s] Salt must be specified")
    SaslException saslSaltMustBeSpecified(String mechName);

    @Message(id = 125, value = "[%s] Authentication rejected (invalid proof)")
    SaslException saslAuthenticationRejectedInvalidProof(String mechName);

    @Message(id = 126, value = "[%s] Client sent extra message")
    SaslException saslClientSentExtraMessage(String mechName);

    @Message(id = 127, value = "[%s] Server sent extra message")
    SaslException saslServerSentExtraMessage(String mechName);

    @Message(id = 128, value = "[%s] Authentication failed")
    SaslException saslAuthenticationFailed(String mechName);

    @Message(id = 129, value = "[%s] Invalid MAC initialization key")
    SaslException saslInvalidMacInitializationKey(String mechName);

    @Message(id = 130, value = "Empty number")
    NumberFormatException emptyNumber();

    @Message(id = 131, value = "Invalid numeric character")
    NumberFormatException invalidNumericCharacter();

    @Message(id = 132, value = "Too big number")
    NumberFormatException tooBigNumber();

    @Message(id = 133, value = "[%s] Cannot get clear password from two way password")
    SaslException saslCannotGetTwoWayPasswordChars(String mechName, @Cause Throwable cause);

    @Message(id = 134, value = "[%s] Hashing algorithm not supported")
    SaslException saslMacAlgorithmNotSupported(String mechName, @Cause Throwable cause);

    @Message(id = 135, value = "[%s] keyword cannot be empty")
    SaslException saslKeywordCannotBeEmpty(String mechName);

    @Message(id = 136, value = "[%s] No value found for keyword: %s")
    SaslException saslNoValueFoundForKeyword(String mechName, String keyword);

    @Message(id = 137, value = "[%s] '=' expected after keyword: %s")
    SaslException saslKeywordNotFolowedByEqual(String mechName, String keyword);

    @Message(id = 138, value = "[%s] Unmatched quote found for value: %s")
    SaslException saslUnmatchedQuoteFoundForValue(String mechName, String value);

    @Message(id = 139, value = "[%s] Expecting comma or linear whitespace after quoted string: %s")
    SaslException saslExpectingCommaOrLinearWhitespaceAfterQuoted(String mechName, String value);

    @Message(id = 140, value = "[%s] MessageType must equal to %d, but it is %d")
    SaslException saslMessageTypeMustEqual(String mechName, int expected, int actual);

    @Message(id = 141, value = "[%s] Bad sequence number while unwrapping: expected %d, but %d received")
    SaslException saslBadSequenceNumberWhileUnwrapping(String mechName, int expected, int actual);

    @Message(id = 142, value = "[%s] Problem during crypt")
    SaslException saslProblemDuringCrypt(String mechName, @Cause Throwable cause);

    @Message(id = 143, value = "[%s] Problem during decrypt")
    SaslException saslProblemDuringDecrypt(String mechName, @Cause Throwable cause);

    @Message(id = 144, value = "[%s] Unknown cipher \"%s\"")
    SaslException saslUnknownCipher(String mechName, String cipher);

    @Message(id = 145, value = "[%s] Cipher \"%s\" unsupported by ")
    SaslException saslUnsupportedCipher(String mechName, String cipher);

    @Message(id = 146, value = "[%s] Problem getting required cipher. Check your transformation mapper settings.")
    SaslException saslProblemGettingRequiredCipher(String mechName, @Cause Throwable cause);

    @Message(id = 147, value = "[%s] No common protection layer between client and server")
    SaslException saslNoCommonProtectionLayer(String mechName);

    @Message(id = 148, value = "[%s] No common cipher between client and server")
    SaslException saslNoCommonCipher(String mechName);

    @Message(id = 149, value = "[%s] No ciphers offered by server")
    SaslException saslNoCiphersOfferedByServer(String mechName);

    @Message(id = 150, value = "[%s] Callback handler not provided user name")
    SaslException saslNotProvidedUserName(String mechName);

    @Message(id = 151, value = "[%s] Callback handler not provided pre-digested password")
    SaslException saslNotProvidedPreDigested(String mechName);

    @Message(id = 152, value = "[%s] Callback handler not provided clear password")
    SaslException saslNotProvidedClearPassword(String mechName);

    @Message(id = 153, value = "[%s] Missing \"%s\" directive")
    SaslException saslMissingDirective(String mechName, String directive);

    @Message(id = 154, value = "[%s] nonce-count must equal to %d, but it is %d")
    SaslException saslNonceCountMustEqual(String mechName, int expected, int actual);

    @Message(id = 155, value = "[%s] Server is set to not support %s charset")
    SaslException saslUnsupportedCharset(String mechName, String charset);

    @Message(id = 156, value = "[%s] Charset can be only \"utf-8\" or unspecified (to use ISO 8859-1)")
    SaslException saslUnknownCharset(String mechName);

    @Message(id = 157, value = "[%s] Client selected realm not offered by server (%s)")
    SaslException saslUnallowedClientRealm(String mechName, String clientRealm);

    @Message(id = 158, value = "[%s] Mismatched digest-uri \"%s\" Expected: \"%s\"")
    SaslException saslMismatchedWrongDigestUri(String mechName, String actual, String expected);

    @Message(id = 159, value = "[%s] Unexpected qop value: \"%s\"")
    SaslException saslUnexpectedQop(String mechName, String qop);

    @Message(id = 160, value = "[%s] Wrapping is not configured")
    IllegalStateException wrappingNotConfigured(String mechName);

    @Message(id = 161, value = "[%s] Authentication name string is too long")
    SaslException saslAuthenticationNameTooLong(String mechName);

    @Message(id = 162, value = "[%s] Authentication name is empty")
    SaslException saslAuthenticationNameIsEmpty(String mechName);

    @Message(id = 163, value = "[%s] Authorization for anonymous access is denied")
    SaslException saslAnonymousAuthorizationDenied(String mechName);

    @Message(id = 164, value = "Required padded length (%d) is less than length of conversion result (%d)")
    IllegalArgumentException requiredNegativePadding(int totalLength, int hexLength);

    @Message(id = 165, value = "Invalid key provided for Digest HMAC computing")
    SaslException saslInvalidKeyForDigestHMAC();

    @Message(id = 166, value = "Unrecognised encoding algorithm")
    ASN1Exception asnUnrecognisedAlgorithm();

    @Message(id = 167, value = "Invalid general name type")
    ASN1Exception asnInvalidGeneralNameType();

    @Message(id = 168, value = "Invalid trusted authority type")
    ASN1Exception asnInvalidTrustedAuthorityType();

    @Message(id = 169, value = "Unexpected ASN.1 tag encountered")
    ASN1Exception asnUnexpectedTag();

    @Message(id = 170, value = "Unable to read X.509 certificate data")
    ASN1Exception asnUnableToReadCertificateData(@Cause Throwable cause);

    @Message(id = 171, value = "Unable to read certificate from URL \"%s\"")
    IOException asnUnableToReadCertificateFromUrl(String url, @Cause Throwable cause);

    @Message(id = 172, value = "Unable to determine subject name from X.509 certificate")
    IllegalStateException unableToDetermineSubjectName(@Cause Throwable cause);

    @Message(id = 173, value = "[%s] Unable to verify client signature")
    SaslException saslUnableToVerifyClientSignature(String mechName, @Cause Throwable cause);

    @Message(id = 174, value = "[%s] Unable to verify server signature")
    SaslException saslUnableToVerifyServerSignature(String mechName, @Cause Throwable cause);

    @Message(id = 175, value = "[%s] Unable to obtain other side certificate from URL \"%s\"")
    SaslException saslUnableToObtainServerCertificate(String mechName, String url, @Cause Throwable cause);

    @Message(id = 176, value = "[%s] Callback handler not provided URL of server certificate")
    SaslException saslCallbackHandlerNotProvidedServerCertificate(String mechName);

    @Message(id = 177, value = "[%s] Callback handler not provided URL of client certificate")
    SaslException saslCallbackHandlerNotProvidedClientCertificate(String mechName);

    @Message(id = 178, value = "[%s] Server identifier mismatch")
    SaslException saslServerIdentifierMismatch(String mechName);

    @Message(id = 179, value = "[%s] Client identifier mismatch")
    SaslException saslClientIdentifierMismatch(String mechName);

    @Message(id = 180, value = "[%s] Unable to determine client name")
    SaslException saslUnableToDetermineClientName(String mechName, @Cause Throwable cause);

    @Message(id = 181, value = "[%s] Callback handler not provided private key")
    SaslException saslCallbackHandlerNotProvidedPrivateKey(String mechName);

    @Message(id = 182, value = "[%s] Unable to create signature")
    SaslException saslUnableToCreateSignature(String mechName, @Cause Throwable cause);

    @Message(id = 183, value = "[%s] Unable to create response token")
    SaslException saslUnableToCreateResponseToken(String mechName, @Cause Throwable cause);

    @Message(id = 184, value = "[%s] Unable to create response token")
    SaslException saslUnableToCreateResponseTokenWithCause(String mechName, @Cause Throwable cause);

    @Message(id = 185, value = "Invalid value for trusted authority type; expected a value between 0 and 4 (inclusive)")
    IllegalArgumentException invalidValueForTrustedAuthorityType();

    @Message(id = 186, value = "Invalid value for a general name type; expected a value between 0 and 8 (inclusive)")
    IllegalArgumentException invalidValueForGeneralNameType();

    @Message(id = 187, value = "Invalid general name for URI type")
    ASN1Exception asnInvalidGeneralNameForUriType(@Cause Throwable cause);

    @Message(id = 188, value = "Invalid general name for IP address type")
    ASN1Exception asnInvalidGeneralNameForIpAddressType();

    @Message(id = 189, value = "IP address general name cannot be resolved")
    ASN1Exception asnIpAddressGeneralNameCannotBeResolved(@Cause Throwable cause);

    @Message(id = 190, value = "Getting SASL mechanisms supported by GSS-API failed")
    SaslException saslGettingSupportedMechanismsFailed(@Cause Throwable cause);

    @Message(id = 191, value = "Unable to initialise Oid of Kerberos V5")
    RuntimeException unableToInitialiseOid(@Cause Throwable cause);

    @Message(id = 192, value = "[%s] Receive buffer requested '%d' is greater than supported maximum '%d'")
    SaslException saslReceiveBufferIsGreaterThanMaximum(String mechName, int requested, int maximum);

    @Message(id = 193, value = "[%s] Unable to wrap message")
    SaslException saslUnableToWrapMessage(String mechName, @Cause Throwable cause);

    @Message(id = 194, value = "[%s] Unable to unwrap message")
    SaslException saslUnableToUnwrapMessage(String mechName, @Cause Throwable cause);

    @Message(id = 195, value = "[%s] Unable to unwrap security layer negotiation message")
    SaslException saslUnableToUnwrapSecurityLayerNegotiationMessage(String mechName, @Cause Throwable cause);

    @Message(id = 196, value = "[%s] Invalid message of length %d on unwrapping")
    SaslException saslInvalidMessageOnUnwrapping(String mechName, int length);

    @Message(id = 197, value = "[%s] Negotiated mechanism was not Kerberos V5")
    SaslException saslNegotiatedMechanismWasNotKerberosV5(String mechName);

    @Message(id = 198, value = "[%s] Insufficient levels of protection available for supported security layers")
    SaslException saslInsufficientQopsAvailable(String mechName);

    @Message(id = 199, value = "[%s] Unable to generate security layer challenge")
    SaslException saslUnableToGenerateChallenge(String mechName, @Cause Throwable cause);

    @Message(id = 200, value = "[%s] Client selected a security layer that was not offered by server")
    SaslException saslSelectedUnofferedQop(String mechName);

    @Message(id = 201, value = "[%s] No security layer selected but message length received")
    SaslException saslNoSecurityLayerButLengthReceived(String mechName);

    @Message(id = 202, value = "[%s] Unable to get maximum size of message before wrap")
    SaslException saslUnableToGetMaximumSizeOfMessage(String mechName, @Cause Throwable cause);

    @Message(id = 203, value = "[%s] Unable to handle response from server")
    SaslException saslUnableToHandleResponseFromServer(String mechName, @Cause Throwable cause);

    @Message(id = 204, value = "[%s] Bad length of message for negotiating security layer")
    SaslException saslBadLengthOfMessageForNegotiatingSecurityLayer(String mechName);

    @Message(id = 205, value = "[%s] No security layer supported by server but maximum message size received: \"%d\"")
    SaslException saslReceivedMaxMessageSizeWhenNoSecurityLayer(String mechName, int length);

    @Message(id = 206, value = "[%s] Failed to read challenge file")
    SaslException saslFailedToReadChallengeFile(String mechName, @Cause Throwable cause);

    @Message(id = 207, value = "[%s] Failed to create challenge file")
    SaslException saslFailedToCreateChallengeFile(String mechName, @Cause Throwable cause);

    @Message(id = 208, value = "Invalid non-ASCII space \"0x%X\"")
    IllegalArgumentException invalidNonAsciiSpace(int input);

    @Message(id = 209, value = "Invalid ASCII control \"0x%X\"")
    IllegalArgumentException invalidAsciiControl(int input);

    @Message(id = 210, value = "Invalid non-ASCII control \"0x%X\"")
    IllegalArgumentException invalidNonAsciiControl(int input);

    @Message(id = 211, value = "Invalid private use character \"0x%X\"")
    IllegalArgumentException invalidPrivateUseCharacter(int input);

    @Message(id = 212, value = "Invalid non-character code point \"0x%X\"")
    IllegalArgumentException invalidNonCharacterCodePoint(int input);

    @Message(id = 213, value = "Invalid surrogate code point \"0x%X\"")
    IllegalArgumentException invalidSurrogateCodePoint(int input);

    @Message(id = 214, value = "Invalid plain text code point \"0x%X\"")
    IllegalArgumentException invalidPlainTextCodePoint(int input);

    @Message(id = 215, value = "Invalid non-canonical code point \"0x%X\"")
    IllegalArgumentException invalidNonCanonicalCodePoint(int input);

    @Message(id = 216, value = "Invalid control character \"0x%X\"")
    IllegalArgumentException invalidControlCharacter(int input);

    @Message(id = 217, value = "Invalid tagging character \"0x%X\"")
    IllegalArgumentException invalidTaggingCharacter(int input);

    @Message(id = 218, value = "Unassigned code point \"0x%X\"")
    IllegalArgumentException unassignedCodePoint(int input);

    @Message(id = 219, value = "Invalid surrogate pair (high at end of string) \"0x%X\"")
    IllegalArgumentException invalidSurrogatePairHightAtEnd(char input);

    @Message(id = 220, value = "Invalid surrogate pair (second is not low) \"0x%X 0x%X\"")
    IllegalArgumentException invalidSurrogatePairSecondIsNotLow(char high, char low);

    @Message(id = 221, value = "Invalid surrogate pair (low without high) \"0x%X\"")
    IllegalArgumentException invalidSurrogatePairLowWithoutHigh(char low);

    @Message(id = 222, value = "Invalid code point \"0x%X\"")
    IllegalArgumentException invalidCodePoint(int input);

    @Message(id = 223, value = "Disallowed R/AL directionality character in L string")
    IllegalArgumentException disallowedRalDirectionalityInL();

    @Message(id = 224, value = "Disallowed L directionality character in R/AL string")
    IllegalArgumentException disallowedLDirectionalityInRal();

    @Message(id = 225, value = "Missing trailing R/AL directionality character")
    IllegalArgumentException missingTrailingRal();

    @Message(id = 226, value = "Invalid escape sequence")
    IllegalArgumentException invalidEscapeSequence();
}
