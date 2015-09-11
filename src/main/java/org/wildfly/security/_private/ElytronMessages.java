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
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import static org.jboss.logging.Logger.Level.WARN;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import javax.security.auth.callback.Callback;
import javax.security.sasl.SaslException;
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
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.http.HttpAuthenticationException;
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

    @Message(id = 2, value = "Parameter %s is empty")
    IllegalArgumentException emptyParameter(String parameter);

    @Message(id = 3, value = "This builder has already been built")
    IllegalStateException builderAlreadyBuilt();

    @Message(id = 4, value = "Unrecognized algorithm \"%s\"")
    IllegalArgumentException unrecognizedAlgorithm(String algorithm);

    @Message(id = 5, value = "Cannot instantiate self-referential factory")
    IllegalStateException cannotInstantiateSelfReferentialFactory();

    @Message(id = 6, value = "Unexpected trailing garbage in X.500 principal")
    IllegalArgumentException unexpectedTrailingGarbageInX500principal();

    @LogMessage(level = WARN)
    @Message(id = 7, value = "Credential destroying failed")
    void credentialDestroyingFailed(@Cause Throwable cause);

    /* auth package */

    @Message(id = 1001, value = "No module found for identifier \"%s\"")
    ConfigXMLParseException noModuleFound(@Param XMLStreamReader reader, @Cause ModuleLoadException e, ModuleIdentifier id);

    @Message(id = 1002, value = "Invalid port number \"%s\" specified for attribute \"%s\" of element \"%s\"; expected a numerical value between 1 and 65535 (inclusive)")
    ConfigXMLParseException xmlInvalidPortNumber(@Param XMLStreamReader reader, String attributeValue, String attributeName, QName elementName);

    @Message(id = 1003, value = "No authentication is in progress")
    IllegalStateException noAuthenticationInProgress();

    @Message(id = 1004, value = "Authentication already complete on this context")
    IllegalStateException alreadyComplete();

    @Message(id = 1005, value = "Realm map does not contain mapping for default realm '%s'")
    IllegalArgumentException realmMapDoesNotContainDefault(String defaultRealm);

    @Message(id = 1006, value = "No realm name found in properties file")
    IOException noRealmFoundInProperties();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 1007, value = "JAAS authentication failed for principal %s")
    void debugJAASAuthenticationFailure(Principal principal, @Cause Throwable cause);

    @Message(id = 1008, value = "Failed to create login context")
    RealmUnavailableException failedToCreateLoginContext(@Cause Throwable cause);

    @Message(id = 1009, value = "Failed to instantiate custom CallbackHandler")
    RealmUnavailableException failedToInstantiateCustomHandler(@Cause Throwable cause);

    @Message(id = 1010, value = "Credential cannot be converted to a password")
    FastUnsupportedCallbackException failedToConvertCredentialToPassword(@Param Callback callback);

    @Message(id = 1011, value = "Unrecognized principal type for %s")
    IllegalArgumentException unrecognizedPrincipalType(Principal principal);

    @Message(id = 1012, value = "Filesystem-backed realm unexpectedly failed to open path \"%s\" for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmFailedToOpen(Path path, String finalName, @Cause IOException cause);

    @Message(id = 1013, value = "Filesystem-backed realm unexpectedly failed to read path \"%s\" for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmFailedToRead(Path path, String finalName, @Cause Exception cause);

    @Message(id = 1014, value = "Invalid empty name given")
    IllegalArgumentException invalidEmptyName();

    @Message(id = 1015, value = "Filesystem-backed realm encountered invalid file content in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidContent(Path path, int lineNumber, String name);

    @Message(id = 1016, value = "Filesystem-backed realm encountered missing required attribute \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmMissingAttribute(String attribute, Path path, int lineNumber, String name);

    @Message(id = 1017, value = "Filesystem-backed realm encountered invalid password format \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidPasswordFormat(String format, Path path, int lineNumber, String name);

    @Message(id = 1018, value = "Filesystem-backed realm encountered invalid password algorithm \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidPasswordAlgorithm(String algorithm, Path path, int lineNumber, String name);

    // 1019

    @Message(id = 1020, value = "Filesystem-backed realm failed to update identity \"%s\"")
    RealmUnavailableException fileSystemUpdatedFailed(String name, @Cause Throwable cause);

    @Message(id = 1021, value = "Filesystem-backed realm failed to delete identity \"%s\"")
    RealmUnavailableException fileSystemRealmDeleteFailed(String name, @Cause IOException e);

    @Message(id = 1022, value = "Filesystem-backed realm failed to find identity \"%s\"")
    RealmUnavailableException fileSystemRealmNotFound(String name);

    @Message(id = 1023, value = "Filesystem-backed realm failed to write to file \"%s\" for identity \"%s\"")
    RealmUnavailableException fileSystemRealmFailedToWrite(Path tempPath, String name, @Cause Exception e);

    @Message(id = 1024, value = "Filesystem-backed realm cannot create duplicate identity for identity \"%s\"")
    RealmUnavailableException fileSystemRealmAlreadyExists(String name, @Cause Throwable e);

    @Message(id = 1025, value = "Filesystem-backed realm encountered invalid certificate format \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmCertificateReadError(String format, Path path, int lineNumber, String name);

    @Message(id = 1026, value = "Filesystem-backed realm encountered invalid key format \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmUnsupportedKeyFormat(String format, Path path, int lineNumber, String name);

    @Message(id = 1027, value = "Filesystem-backed realm encountered invalid key algorithm for format \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmUnsupportedKeyAlgorithm(String format, Path path, int lineNumber, String name, @Cause Exception e);

    @Message(id = 1028, value = "Invalid port number \"%d\"")
    IllegalArgumentException invalidPortNumber(int port);

    @Message(id = 1029, value = "Invalid host specification \"%s\"")
    IllegalArgumentException invalidHostSpec(String hostSpec);

    @Message(id = 1030, value = "Unable to read credential")
    IOException unableToReadCredential(@Cause Exception e);

    @Message(id = 1031, value = "Missing reference in extends")
    IllegalArgumentException missingReferenceInExtends();

    @Message(id = 1032, value = "Invalid combination of obtainable and verifiable")
    IllegalArgumentException invalidCombinationOfObtainableAndVerifiable();

    @Message(id = 1033, value = "User does not exist")
    IllegalStateException userDoesNotExist();

    @Message(id = 1034, value = "Invalid credential type specified")
    IllegalStateException invalidCredentialTypeSpecified();

    @Message(id = 1035, value = "Unable to create key manager")
    IOException unableToCreateKeyManager(@Cause Exception e);

    @Message(id = 1036, value = "Unable to create trust manager")
    IOException unableToCreateTrustManager(@Cause Exception e);

    //1037

    @Message(id = 1038, value = "Could get not RSA key from query")
    RuntimeException couldNotGetRsaKeyFromQuery(@Cause Throwable cause);

    @Message(id = 1039, value = "Invalid algorithm \"%s\"")
    RuntimeException invalidAlgorithm(String algorithm, @Cause Throwable cause);

    @Message(id = 1040, value = "Could not parse private key")
    RuntimeException couldNotParsePrivateKey(@Cause Throwable cause);

    @Message(id = 1041, value = "Could not obtain credential")
    RuntimeException couldNotObtainCredential();

    @Message(id = 1042, value = "Could not obtain credential")
    RuntimeException couldNotObtainCredentialWithCause(@Cause Throwable cause);

    @Message(id = 1043, value = "Invalid password key specification for algorithm \"%s\"")
    RuntimeException invalidPasswordKeySpecificationForAlgorithm(String algorithm, @Cause Throwable cause);

    @Message(id = 1044, value = "Salt is expected when creating \"%s\" passwords")
    RuntimeException saltIsExpectedWhenCreatingPasswords(String type);

    @Message(id = 1045, value = "Could not obtain PasswordFactory for algorithm \"%s\"")
    RuntimeException couldNotObtainPasswordFactoryForAlgorithm(String algorithm, @Cause Throwable cause);

    @Message(id = 1046, value = "Unknown password type or algorithm \"%s\"")
    InvalidKeyException unknownPasswordTypeOrAlgorithm(String algorithm);

    @Message(id = 1047, value = "Password-based credentials must be either a char[] or ClearPassword")
    RuntimeException passwordBasedCredentialsMustBeCharsOrClearPassword();

    @Message(id = 1048, value = "Invalid password key for algorithm \"%s\"")
    RuntimeException invalidPasswordKeyForAlgorithm(String algorithm, @Cause Throwable cause);

    @Message(id = 1049, value = "Could not open connection")
    RuntimeException couldNotOpenConnection(@Cause Throwable cause);

    @Message(id = 1050, value = "Could not execute query \"%s\"")
    RuntimeException couldNotExecuteQuery(String sql, @Cause Throwable cause);

    // 1051

    @Message(id = 1052, value = "Unexpected error when processing authentication query \"%s\"")
    RuntimeException unexpectedErrorWhenProcessingAuthenticationQuery(String sql, @Cause Throwable cause);

    @Message(id = 1053, value = "Insufficient data to form a digest and a salt")
    InvalidKeySpecException insufficientDataToFormDigestAndSalt();

    @Message(id = 1054, value = "Invalid salt \"%s%s\"")
    IllegalArgumentException invalidSalt(char lo, char hi);

    @Message(id = 1055, value = "Invalid rounds \"%s%s%s%s\"")
    IllegalArgumentException invalidRounds(char b0, char b1, char b2, char b3);

    @Message(id = 1056, value = "Invalid salt \"%s%s%s%s\"")
    IllegalArgumentException invalidSalt(char b0, char b1, char b2, char b3);

    @Message(id = 1057, value = "No DirContextFactory set")
    IllegalStateException noDirContextFactorySet();

    @Message(id = 1058, value = "No principal mapping definition")
    IllegalStateException noPrincipalMappingDefinition();

    // 1059

    @Message(id = 1060, value = "Could not obtain principal")
    RuntimeException couldNotObtainPrincipal();

    // 1061

    @Message(id = 1062, value = "No provider URL has been set")
    IllegalStateException noProviderUrlSet();

    // 1063

    @Message(id = 1064, value = "Invalid name")
    IllegalArgumentException invalidName();

    @Message(id = 1065, value = "Pattern requires a capture group")
    IllegalArgumentException patternRequiresCaptureGroup();

    @LogMessage(level = WARN)
    @Message(id = 1066, value = "Invalid string count for mechanism database entry \"%s\"")
    void warnInvalidStringCountForMechanismDatabaseEntry(String name);

    @LogMessage(level = WARN)
    @Message(id = 1067, value = "Invalid key exchange \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidKeyExchangeForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1068, value = "Invalid authentication \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidAuthenticationForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1069, value = "Invalid encryption \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidEncryptionForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1070, value = "Invalid digest \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidDigestForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1071, value = "Invalid protocol \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidProtocolForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1072, value = "Invalid level \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidLevelForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1073, value = "Invalid strength bits \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidStrengthBitsForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1074, value = "Invalid algorithm bits \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidAlgorithmBitsForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1075, value = "Invalid duplicate mechanism database entry \"%s\"")
    void warnInvalidDuplicateMechanismDatabaseEntry(String name);

    @LogMessage(level = WARN)
    @Message(id = 1076, value = "Invalid duplicate OpenSSL-style alias \"%s\" for mechanism database entry \"%s\" (original is \"%s\")")
    void warnInvalidDuplicateOpenSslStyleAliasForMechanismDatabaseEntry(String alias, String name, String originalName);

    @LogMessage(level = WARN)
    @Message(id = 1077, value = "Invalid alias \"%s\" for missing mechanism database entry \"%s\"")
    void warnInvalidAliasForMissingMechanismDatabaseEntry(String value, String name);

    @Message(id = 1078, value = "Ldap-backed realm failed to obtain identity from server")
    RuntimeException ldapRealmFailedObtainIdentityFromServer(@Cause Throwable cause);

    @Message(id = 1079, value = "Ldap-backed realm failed to obtain attributes for entry [%s]")
    RuntimeException ldapRealmFailedObtainAttributes(String dn, @Cause Throwable cause);

    @Message(id = 1080, value = "Attribute [%s] value [%s] must be in X.500 format in order to obtain RDN [%s].")
    RuntimeException ldapRealmInvalidRdnForAttribute(String attributeName, String value, String rdn);

    @Message(id = 1081, value = "Filesystem-backed realm encountered invalid OTP definition in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidOtpDefinition(Path path, int lineNumber, String name, @Cause Throwable cause);

    @Message(id = 1082, value = "Filesystem-backed realm encountered invalid OTP algorithm \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidOtpAlgorithm(String algorithm, Path path, int lineNumber, String name, @Cause Throwable cause);

    @Message(id = 1083, value = "Ldap-backed realm cannot to obtain not existing identity \"%s\"")
    RealmUnavailableException ldapRealmIdentityNotExists(String identity);

    @Message(id = 1084, value = "Error while consuming results from search. SearchDn [%s], Filter [%s], Filter Args [%s].")
    RuntimeException ldapRealmErrorWhileConsumingResultsFromSearch(String searchDn, String filter, String filterArgs, @Cause Throwable cause);

    @Message(id = 1085, value = "No Ldap-backed realm's persister support credential of type \"%s\" and algorithm \"%s\"")
    RealmUnavailableException ldapRealmsPersisterNotSupportCredentialTypeAndAlgorithm(String type, String algorithm);

    @Message(id = 1086, value = "Persisting credential %s into Ldap-backed realm failed. Identity dn: \"%s\"")
    RealmUnavailableException ldapRealmCredentialPersistingFailed(String credential, String dn, @Cause Throwable cause);

    @Message(id = 1087, value = "Clearing credentials from Ldap-backed realm failed. Identity dn: \"%s\"")
    RealmUnavailableException ldapRealmCredentialClearingFailed(String dn, @Cause Throwable cause);

    /* keystore package */

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

    @Message(id = 2010, value = "Unknown key store specified")
    IllegalArgumentException unknownKeyStoreSpecified();

    @Message(id = 2011, value = "Failed to load keystore data")
    KeyStoreException failedToLoadKeyStoreData(@Cause Throwable cause);

    @Message(id = 2012, value = "Secret keys not supported")
    KeyStoreException secretKeysNotSupported();

    @Message(id = 2013, value = "Direct key storage not supported")
    KeyStoreException directKeyStorageNotSupported();

    @Message(id = 2014, value = "Only password storage is supported")
    KeyStoreException onlyPasswordStorageIsSupported();

    /* util package */

    @Message(id = 3001, value = "Unexpected padding")
    DecodeException unexpectedPadding();

    @Message(id = 3002, value = "Expected padding")
    DecodeException expectedPadding();

    @Message(id = 3003, value = "Incomplete decode")
    DecodeException incompleteDecode();

    @Message(id = 3004, value = "Expected %d padding characters")
    DecodeException expectedPaddingCharacters(int numExpected);

    @Message(id = 3005, value = "Invalid base 32 character")
    DecodeException invalidBase32Character();

    @Message(id = 3006, value = "Expected an even number of hex characters")
    DecodeException expectedEvenNumberOfHexCharacters();

    @Message(id = 3007, value = "Invalid hex character")
    DecodeException invalidHexCharacter();

    @Message(id = 3008, value = "Expected two padding characters")
    DecodeException expectedTwoPaddingCharacters();

    @Message(id = 3009, value = "Invalid base 64 character")
    DecodeException invalidBase64Character();

    /* ssl package */

    @Message(id = 4001, value = "No algorithm found matching TLS/SSL protocol selection criteria")
    NoSuchAlgorithmException noAlgorithmForSslProtocol();

    @Message(id = 4002, value = "Empty certificate chain is not trusted")
    CertificateException emptyChainNotTrusted();

    @Message(id = 4003, value = "Certificate not trusted due to realm failure for principal %s")
    CertificateException notTrustedRealmProblem(@Cause RealmUnavailableException e, Principal principal);

    @Message(id = 4004, value = "Credential validation failed; certificate is not trusted for principal %s")
    CertificateException notTrusted(Principal principal);

    @Message(id = 4005, value = "No default trust manager available")
    NoSuchAlgorithmException noDefaultTrustManager();

    @Message(id = 4006, value = "No host for SSL connection")
    SSLHandshakeException noHostForSslConnection();

    @Message(id = 4007, value = "SSL channel is closed")
    SSLException sslClosed();

    @Message(id = 4008, value = "Initial SSL/TLS data is not a handshake record")
    SSLHandshakeException notHandshakeRecord();

    @Message(id = 4009, value = "Initial SSL/TLS handshake record is invalid")
    SSLHandshakeException invalidHandshakeRecord();

    @Message(id = 4010, value = "Initial SSL/TLS handshake spans multiple records")
    SSLHandshakeException multiRecordSSLHandshake();

    @Message(id = 4011, value = "Expected \"client hello\" record")
    SSLHandshakeException expectedClientHello();

    @Message(id = 4012, value = "Unsupported SSL/TLS record")
    SSLHandshakeException unsupportedSslRecord();

    @Message(id = 4013, value = "Invalid SNI extension")
    SSLProtocolException invalidSniExt();

    @Message(id = 4014, value = "Not enough data in record to fill declared item size")
    SSLProtocolException notEnoughData();

    @Message(id = 4015, value = "Empty host name in SNI record data")
    SSLProtocolException emptyHostNameSni();

    @Message(id = 4016, value = "Duplicated SNI server name of type %d")
    SSLProtocolException duplicatedSniServerName(int type);

    @Message(id = 4017, value = "Unknown authentication name \"%s\"")
    IllegalArgumentException unknownAuthenticationName(String name);

    @Message(id = 4018, value = "Unknown encryption name \"%s\"")
    IllegalArgumentException unknownEncryptionName(String name);

    @Message(id = 4019, value = "Unknown key exchange name \"%s\"")
    IllegalArgumentException unknownKeyExchangeName(String name);

    @Message(id = 4020, value = "Mechanism \"%s\" not supported by transformation mapper")
    IllegalArgumentException mechanismNotSupported(String mechanism);

    @Message(id = 4021, value = "Invalid index %d")
    IndexOutOfBoundsException invalidIndex(int index);

    @Message(id = 4022, value = "Invalid socket address type for URI")
    IllegalArgumentException invalidSocketAddressTypeForUri();

    @Message(id = 4023, value = "Too large")
    IllegalStateException tooLarge();

    /* sasl package */

    @Message(id = 5001, value = "[%s] SASL exchange received a message after authentication was already complete")
    SaslException saslMessageAfterComplete(String mechName);

    @Message(id = 5002, value = "[%s] SASL user name contains an invalid or disallowed character")
    SaslException saslUserNameContainsInvalidCharacter(String mechName);

    // 5003

    @Message(id = 5004, value = "[%s] SASL authorization failed")
    SaslException saslAuthorizationFailed(String mechName, @Cause Throwable cause);

    @Message(id = 5005, value = "[%s] SASL authentication is not yet complete")
    IllegalStateException saslAuthenticationNotComplete(String mechName);

    @Message(id = 5006, value = "[%s] SASL mechanism not support security layer (wrapping/unwrapping)")
    SaslException saslNoSecurityLayer(String mechName);

    @Message(id = 5007, value = "[%s] Invalid SASL negotiation message received")
    SaslException saslInvalidMessageReceived(String mechName);

    @Message(id = 5008, value = "[%s] No SASL login name was given")
    SaslException saslNoLoginNameGiven(String mechName);

    @Message(id = 5009, value = "[%s] No SASL password was given")
    SaslException saslNoPasswordGiven(String mechName);

    @Message(id = 5010, value = "[%s] SASL authentication failed due to one or more malformed fields")
    SaslException saslMalformedFields(String mechName, @Cause IllegalArgumentException ex);

    @Message(id = 5011, value = "[%s] SASL message is too long")
    SaslException saslMessageTooLong(String mechName);

    @Message(id = 5012, value = "[%s] SASL server-side authentication failed")
    SaslException saslServerSideAuthenticationFailed(String mechName, @Cause Exception e);

    @Message(id = 5013, value = "[%s] SASL password not verified")
    SaslException saslPasswordNotVerified(String mechName);

    @Message(id = 5014, value = "[%s] SASL authorization failed: \"%s\" is not authorized to act on behalf of \"%s\"")
    SaslException saslAuthorizationFailed(String mechName, String userName, String authorizationId);

    @Message(id = 5015, value = "Unexpected character U+%04x at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnexpectedChar(int codePoint, int offset, String string);

    @Message(id = 5016, value = "Unrecognized token \"%s\" in mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnknownToken(String word, String string);

    @Message(id = 5017, value = "Token \"%s\" not allowed at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorTokenNotAllowed(String token, int offset, String string);

    // 5018

    @Message(id = 5019, value = "[%s] Proxied SASL authentication failed")
    SaslException saslProxyAuthenticationFailed(String mechName);

    // 5020

    // 5021

    @Message(id = 5022, value = "[%s] Initial challenge must be empty")
    SaslException saslInitialChallengeMustBeEmpty(String mechName);

    @Message(id = 5023, value = "[%s] Unable to set channel binding")
    SaslException saslUnableToSetChannelBinding(String mechName, @Cause Exception e);

    @Message(id = 5024, value = "Failed to determine channel binding status")
    SaslException saslFailedToDetermineChannelBindingStatus(@Cause Exception e);

    @Message(id = 5025, value = "[%s] Mutual authentication not enabled")
    SaslException saslMutualAuthenticationNotEnabled(String mechName);

    @Message(id = 5026, value = "[%s] Unable to map SASL mechanism name to a GSS-API OID")
    SaslException saslMechanismToOidMappingFailed(String mechName, @Cause Exception e);

    @Message(id = 5027, value = "[%s] Unable to dispose of GSSContext")
    SaslException saslUnableToDisposeGssContext(String mechName, @Cause Exception e);

    @Message(id = 5028, value = "[%s] Unable to create name for acceptor")
    SaslException saslUnableToCreateNameForAcceptor(String mechName, @Cause Exception e);

    @Message(id = 5029, value = "[%s] Unable to create GSSContext")
    SaslException saslUnableToCreateGssContext(String mechName, @Cause Exception e);

    @Message(id = 5030, value = "[%s] Unable to set GSSContext request flags")
    SaslException saslUnableToSetGssContextRequestFlags(String mechName, @Cause Exception e);

    @Message(id = 5031, value = "[%s] Unable to accept SASL client message")
    SaslException saslUnableToAcceptClientMessage(String mechName, @Cause Exception e);

    @Message(id = 5032, value = "[%s] GSS-API mechanism mismatch between SASL client and server")
    SaslException saslGssApiMechanismMismatch(String mechName);

    @Message(id = 5033, value = "[%s] Channel binding not supported for this SASL mechanism")
    SaslException saslChannelBindingNotSupported(String mechName);

    @Message(id = 5034, value = "[%s] Channel binding type mismatch between SASL client and server")
    SaslException saslChannelBindingTypeMismatch(String mechName);

    @Message(id = 5035, value = "[%s] Channel binding not provided by client")
    SaslException saslChannelBindingNotProvided(String mechName);

    @Message(id = 5036, value = "[%s] Unable to determine peer name")
    SaslException saslUnableToDeterminePeerName(String mechName, @Cause Exception e);

    @Message(id = 5037, value = "[%s] SASL client refuses to initiate authentication")
    SaslException saslClientRefusesToInitiateAuthentication(String mechName);

    @Message(id = 5038, value = "[%s] Nonces do not match")
    SaslException saslNoncesDoNotMatch(String mechName);

    @Message(id = 5039, value = "[%s] Server nonce is too short")
    SaslException saslServerNonceIsTooShort(String mechName);

    @Message(id = 5040, value = "[%s] Iteration count %d is below the minimum of %d")
    SaslException saslIterationCountIsTooLow(String mechName, int iterationCount, int minimumIterationCount);

    @Message(id = 5041, value = "[%s] Iteration count %d is above the maximum of %d")
    SaslException saslIterationCountIsTooHigh(String mechName, int iterationCount, int maximumIterationCount);

    @Message(id = 5042, value = "[%s] Extensions unsupported")
    SaslException saslExtensionsUnsupported(String mechName);

    @Message(id = 5043, value = "[%s] Invalid server message")
    SaslException saslInvalidServerMessage(String mechName);

    @Message(id = 5044, value = "[%s] Invalid server message")
    SaslException saslInvalidServerMessageWithCause(String mechName, @Cause Throwable cause);

    @Message(id = 5045, value = "[%s] Invalid client message")
    SaslException saslInvalidClientMessage(String mechName);

    @Message(id = 5046, value = "[%s] Invalid client message")
    SaslException saslInvalidClientMessageWithCause(String mechName, @Cause Throwable cause);

    // 5047

    @Message(id = 5048, value = "[%s] Server rejected authentication")
    SaslException saslServerRejectedAuthentication(String mechName);

    @Message(id = 5049, value = "[%s] Server authenticity cannot be verified")
    SaslException saslServerAuthenticityCannotBeVerified(String mechName);

    @Message(id = 5050, value = "[%s] Callback handler does not support user name")
    SaslException saslCallbackHandlerDoesNotSupportUserName(String mechName, @Cause Throwable cause);

    @Message(id = 5051, value = "[%s] Callback handler does not support credential acquisition")
    SaslException saslCallbackHandlerDoesNotSupportCredentialAcquisition(String mechName, @Cause Throwable cause);

    @Message(id = 5052, value = "[%s] Callback handler does not support authorization")
    SaslException saslAuthorizationUnsupported(String mechName, @Cause Throwable cause);

    @Message(id = 5053, value = "[%s] Callback handler failed for unknown reason")
    SaslException saslCallbackHandlerFailedForUnknownReason(String mechName, @Cause Throwable cause);

    @Message(id = 5054, value = "[%s] Salt must be specified")
    SaslException saslSaltMustBeSpecified(String mechName);

    @Message(id = 5055, value = "[%s] Authentication rejected (invalid proof)")
    SaslException saslAuthenticationRejectedInvalidProof(String mechName);

    @Message(id = 5056, value = "[%s] Client sent extra message")
    SaslException saslClientSentExtraMessage(String mechName);

    @Message(id = 5057, value = "[%s] Server sent extra message")
    SaslException saslServerSentExtraMessage(String mechName);

    @Message(id = 5058, value = "[%s] Authentication failed")
    SaslException saslAuthenticationFailed(String mechName);

    @Message(id = 5059, value = "[%s] Invalid MAC initialization key")
    SaslException saslInvalidMacInitializationKey(String mechName);

    @Message(id = 5060, value = "Empty number")
    NumberFormatException emptyNumber();

    @Message(id = 5061, value = "Invalid numeric character")
    NumberFormatException invalidNumericCharacter();

    @Message(id = 5062, value = "Too big number")
    NumberFormatException tooBigNumber();

    @Message(id = 5063, value = "[%s] Cannot get clear password from two way password")
    SaslException saslCannotGetTwoWayPasswordChars(String mechName, @Cause Throwable cause);

    @Message(id = 5064, value = "[%s] Hashing algorithm not supported")
    SaslException saslMacAlgorithmNotSupported(String mechName, @Cause Throwable cause);

    @Message(id = 5065, value = "[%s] keyword cannot be empty")
    SaslException saslKeywordCannotBeEmpty(String mechName);

    @Message(id = 5066, value = "[%s] No value found for keyword: %s")
    SaslException saslNoValueFoundForKeyword(String mechName, String keyword);

    @Message(id = 5067, value = "[%s] '=' expected after keyword: %s")
    SaslException saslKeywordNotFollowedByEqual(String mechName, String keyword);

    @Message(id = 5068, value = "[%s] Unmatched quote found for value: %s")
    SaslException saslUnmatchedQuoteFoundForValue(String mechName, String value);

    @Message(id = 5069, value = "[%s] Expecting comma or linear whitespace after quoted string: %s")
    SaslException saslExpectingCommaOrLinearWhitespaceAfterQuoted(String mechName, String value);

    @Message(id = 5070, value = "[%s] MessageType must equal to %d, but it is %d")
    SaslException saslMessageTypeMustEqual(String mechName, int expected, int actual);

    @Message(id = 5071, value = "[%s] Bad sequence number while unwrapping: expected %d, but %d received")
    SaslException saslBadSequenceNumberWhileUnwrapping(String mechName, int expected, int actual);

    @Message(id = 5072, value = "[%s] Problem during crypt")
    SaslException saslProblemDuringCrypt(String mechName, @Cause Throwable cause);

    @Message(id = 5073, value = "[%s] Problem during decrypt")
    SaslException saslProblemDuringDecrypt(String mechName, @Cause Throwable cause);

    @Message(id = 5074, value = "[%s] Unknown cipher \"%s\"")
    SaslException saslUnknownCipher(String mechName, String cipher);

    // 5075

    @Message(id = 5076, value = "[%s] Problem getting required cipher. Check your transformation mapper settings.")
    SaslException saslProblemGettingRequiredCipher(String mechName, @Cause Throwable cause);

    @Message(id = 5077, value = "[%s] No common protection layer between client and server")
    SaslException saslNoCommonProtectionLayer(String mechName);

    @Message(id = 5078, value = "[%s] No common cipher between client and server")
    SaslException saslNoCommonCipher(String mechName);

    @Message(id = 5079, value = "[%s] No ciphers offered by server")
    SaslException saslNoCiphersOfferedByServer(String mechName);

    @Message(id = 5080, value = "[%s] Callback handler not provided user name")
    SaslException saslNotProvidedUserName(String mechName);

    @Message(id = 5081, value = "[%s] Callback handler not provided pre-digested password")
    SaslException saslNotProvidedPreDigested(String mechName);

    @Message(id = 5082, value = "[%s] Callback handler not provided clear password")
    SaslException saslNotProvidedClearPassword(String mechName);

    @Message(id = 5083, value = "[%s] Missing \"%s\" directive")
    SaslException saslMissingDirective(String mechName, String directive);

    @Message(id = 5084, value = "[%s] nonce-count must equal to %d, but it is %d")
    SaslException saslNonceCountMustEqual(String mechName, int expected, int actual);

    @Message(id = 5085, value = "[%s] Server is set to not support %s charset")
    SaslException saslUnsupportedCharset(String mechName, String charset);

    @Message(id = 5086, value = "[%s] Charset can be only \"utf-8\" or unspecified (to use ISO 8859-1)")
    SaslException saslUnknownCharset(String mechName);

    @Message(id = 5087, value = "[%s] Client selected realm not offered by server (%s)")
    SaslException saslUnallowedClientRealm(String mechName, String clientRealm);

    @Message(id = 5088, value = "[%s] Mismatched digest-uri \"%s\" Expected: \"%s\"")
    SaslException saslMismatchedWrongDigestUri(String mechName, String actual, String expected);

    @Message(id = 5089, value = "[%s] Unexpected qop value: \"%s\"")
    SaslException saslUnexpectedQop(String mechName, String qop);

    @Message(id = 5090, value = "[%s] Wrapping is not configured")
    IllegalStateException wrappingNotConfigured(String mechName);

    @Message(id = 5091, value = "[%s] Authentication name string is too long")
    SaslException saslAuthenticationNameTooLong(String mechName);

    @Message(id = 5092, value = "[%s] Authentication name is empty")
    SaslException saslAuthenticationNameIsEmpty(String mechName);

    @Message(id = 5093, value = "[%s] Authorization for anonymous access is denied")
    SaslException saslAnonymousAuthorizationDenied(String mechName);

    @Message(id = 5094, value = "Required padded length (%d) is less than length of conversion result (%d)")
    IllegalArgumentException requiredNegativePadding(int totalLength, int hexLength);

    @Message(id = 5095, value = "Invalid key provided for Digest HMAC computing")
    SaslException saslInvalidKeyForDigestHMAC();

    @Message(id = 5096, value = "Unable to read certificate from URL \"%s\"")
    IOException asnUnableToReadCertificateFromUrl(String url, @Cause Throwable cause);

    @Message(id = 5097, value = "Unable to determine subject name from X.509 certificate")
    IllegalStateException unableToDetermineSubjectName(@Cause Throwable cause);

    @Message(id = 5098, value = "[%s] Unable to verify client signature")
    SaslException saslUnableToVerifyClientSignature(String mechName, @Cause Throwable cause);

    @Message(id = 5099, value = "[%s] Unable to verify server signature")
    SaslException saslUnableToVerifyServerSignature(String mechName, @Cause Throwable cause);

    @Message(id = 5100, value = "[%s] Unable to obtain other side certificate from URL \"%s\"")
    SaslException saslUnableToObtainServerCertificate(String mechName, String url, @Cause Throwable cause);

    @Message(id = 5101, value = "[%s] Callback handler not provided URL of server certificate")
    SaslException saslCallbackHandlerNotProvidedServerCertificate(String mechName);

    @Message(id = 5102, value = "[%s] Callback handler not provided URL of client certificate")
    SaslException saslCallbackHandlerNotProvidedClientCertificate(String mechName);

    @Message(id = 5103, value = "[%s] Server identifier mismatch")
    SaslException saslServerIdentifierMismatch(String mechName);

    @Message(id = 5104, value = "[%s] Client identifier mismatch")
    SaslException saslClientIdentifierMismatch(String mechName);

    @Message(id = 5105, value = "[%s] Unable to determine client name")
    SaslException saslUnableToDetermineClientName(String mechName, @Cause Throwable cause);

    @Message(id = 5106, value = "[%s] Callback handler not provided private key")
    SaslException saslCallbackHandlerNotProvidedPrivateKey(String mechName);

    @Message(id = 5107, value = "[%s] Unable to create signature")
    SaslException saslUnableToCreateSignature(String mechName, @Cause Throwable cause);

    @Message(id = 5108, value = "[%s] Unable to create response token")
    SaslException saslUnableToCreateResponseToken(String mechName, @Cause Throwable cause);

    @Message(id = 5109, value = "[%s] Unable to create response token")
    SaslException saslUnableToCreateResponseTokenWithCause(String mechName, @Cause Throwable cause);

    @Message(id = 5110, value = "Invalid value for trusted authority type; expected a value between 0 and 4 (inclusive)")
    IllegalArgumentException invalidValueForTrustedAuthorityType();

    @Message(id = 5111, value = "Invalid value for a general name type; expected a value between 0 and 8 (inclusive)")
    IllegalArgumentException invalidValueForGeneralNameType();

    @Message(id = 5112, value = "Getting SASL mechanisms supported by GSS-API failed")
    SaslException saslGettingSupportedMechanismsFailed(@Cause Throwable cause);

    @Message(id = 5113, value = "Unable to initialize OID of Kerberos V5")
    RuntimeException unableToInitialiseOid(@Cause Throwable cause);

    @Message(id = 5114, value = "[%s] Receive buffer requested '%d' is greater than supported maximum '%d'")
    SaslException saslReceiveBufferIsGreaterThanMaximum(String mechName, int requested, int maximum);

    @Message(id = 5115, value = "[%s] Unable to wrap message")
    SaslException saslUnableToWrapMessage(String mechName, @Cause Throwable cause);

    @Message(id = 5116, value = "[%s] Unable to unwrap message")
    SaslException saslUnableToUnwrapMessage(String mechName, @Cause Throwable cause);

    @Message(id = 5117, value = "[%s] Unable to unwrap security layer negotiation message")
    SaslException saslUnableToUnwrapSecurityLayerNegotiationMessage(String mechName, @Cause Throwable cause);

    @Message(id = 5118, value = "[%s] Invalid message of length %d on unwrapping")
    SaslException saslInvalidMessageOnUnwrapping(String mechName, int length);

    @Message(id = 5119, value = "[%s] Negotiated mechanism was not Kerberos V5")
    SaslException saslNegotiatedMechanismWasNotKerberosV5(String mechName);

    @Message(id = 5120, value = "[%s] Insufficient levels of protection available for supported security layers")
    SaslException saslInsufficientQopsAvailable(String mechName);

    @Message(id = 5121, value = "[%s] Unable to generate security layer challenge")
    SaslException saslUnableToGenerateChallenge(String mechName, @Cause Throwable cause);

    @Message(id = 5122, value = "[%s] Client selected a security layer that was not offered by server")
    SaslException saslSelectedUnofferedQop(String mechName);

    @Message(id = 5123, value = "[%s] No security layer selected but message length received")
    SaslException saslNoSecurityLayerButLengthReceived(String mechName);

    @Message(id = 5124, value = "[%s] Unable to get maximum size of message before wrap")
    SaslException saslUnableToGetMaximumSizeOfMessage(String mechName, @Cause Throwable cause);

    @Message(id = 5125, value = "[%s] Unable to handle response from server")
    SaslException saslUnableToHandleResponseFromServer(String mechName, @Cause Throwable cause);

    @Message(id = 5126, value = "[%s] Bad length of message for negotiating security layer")
    SaslException saslBadLengthOfMessageForNegotiatingSecurityLayer(String mechName);

    @Message(id = 5127, value = "[%s] No security layer supported by server but maximum message size received: \"%d\"")
    SaslException saslReceivedMaxMessageSizeWhenNoSecurityLayer(String mechName, int length);

    @Message(id = 5128, value = "[%s] Failed to read challenge file")
    SaslException saslFailedToReadChallengeFile(String mechName, @Cause Throwable cause);

    @Message(id = 5129, value = "[%s] Failed to create challenge file")
    SaslException saslFailedToCreateChallengeFile(String mechName, @Cause Throwable cause);

    @Message(id = 5130, value = "Invalid non-ASCII space \"0x%X\"")
    IllegalArgumentException invalidNonAsciiSpace(int input);

    @Message(id = 5131, value = "Invalid ASCII control \"0x%X\"")
    IllegalArgumentException invalidAsciiControl(int input);

    @Message(id = 5132, value = "Invalid non-ASCII control \"0x%X\"")
    IllegalArgumentException invalidNonAsciiControl(int input);

    @Message(id = 5133, value = "Invalid private use character \"0x%X\"")
    IllegalArgumentException invalidPrivateUseCharacter(int input);

    @Message(id = 5134, value = "Invalid non-character code point \"0x%X\"")
    IllegalArgumentException invalidNonCharacterCodePoint(int input);

    @Message(id = 5135, value = "Invalid surrogate code point \"0x%X\"")
    IllegalArgumentException invalidSurrogateCodePoint(int input);

    @Message(id = 5136, value = "Invalid plain text code point \"0x%X\"")
    IllegalArgumentException invalidPlainTextCodePoint(int input);

    @Message(id = 5137, value = "Invalid non-canonical code point \"0x%X\"")
    IllegalArgumentException invalidNonCanonicalCodePoint(int input);

    @Message(id = 5138, value = "Invalid control character \"0x%X\"")
    IllegalArgumentException invalidControlCharacter(int input);

    @Message(id = 5139, value = "Invalid tagging character \"0x%X\"")
    IllegalArgumentException invalidTaggingCharacter(int input);

    @Message(id = 5140, value = "Unassigned code point \"0x%X\"")
    IllegalArgumentException unassignedCodePoint(int input);

    @Message(id = 5141, value = "Invalid surrogate pair (high at end of string) \"0x%X\"")
    IllegalArgumentException invalidSurrogatePairHightAtEnd(char input);

    @Message(id = 5142, value = "Invalid surrogate pair (second is not low) \"0x%X 0x%X\"")
    IllegalArgumentException invalidSurrogatePairSecondIsNotLow(char high, char low);

    @Message(id = 5143, value = "Invalid surrogate pair (low without high) \"0x%X\"")
    IllegalArgumentException invalidSurrogatePairLowWithoutHigh(char low);

    @Message(id = 5144, value = "Invalid code point \"0x%X\"")
    IllegalArgumentException invalidCodePoint(int input);

    @Message(id = 5145, value = "Disallowed R/AL directionality character in L string")
    IllegalArgumentException disallowedRalDirectionalityInL();

    @Message(id = 5146, value = "Disallowed L directionality character in R/AL string")
    IllegalArgumentException disallowedLDirectionalityInRal();

    @Message(id = 5147, value = "Missing trailing R/AL directionality character")
    IllegalArgumentException missingTrailingRal();

    @Message(id = 5148, value = "Invalid escape sequence")
    IllegalArgumentException invalidEscapeSequence();

    // 5149

    @Message(id = 5150, value = "[%s] SASL authorization ID is too long")
    SaslException saslAuthorizationIdTooLong(String mechName);

    @Message(id = 5151, value = "Invalid OTP algorithm \"%s\"")
    SaslException saslInvalidOTPAlgorithm(String algorithm);

    @Message(id = 5152, value = "Invalid OTP response type")
    SaslException saslInvalidOTPResponseType();

    @Message(id = 5153, value = "[%s] Incorrect parity in SASL client message")
    SaslException saslIncorrectParity(String mechName);

    @Message(id = 5154, value = "[%s] Invalid character in seed")
    SaslException saslInvalidCharacterInSeed(String mechName);

    @Message(id = 5155, value = "Invalid OTP seed, must be between 1 and 16 characters long")
    SaslException saslInvalidOTPSeed();

    @Message(id = 5156, value = "Invalid OTP pass phrase, must be between 10 and 63 characters long")
    SaslException saslInvalidOTPPassPhrase();

    @Message(id = 5157, value = "Invalid OTP sequence number")
    SaslException saslInvalidOTPSequenceNumber();

    @Message(id = 5158, value = "Invalid OTP")
    SaslException saslInvalidOTP();

    @Message(id = 5159, value = "OTP pass phrase and seed must not match")
    SaslException saslOTPPassPhraseAndSeedMustNotMatch();

    @Message(id = 5160, value = "Invalid OTP alternate dictionary")
    SaslException saslInvalidOTPAlternateDictionary();

    @Message(id = 5161, value = "[%s] Unable to retrieve password for \"%s\"")
    SaslException saslUnableToRetrievePassword(String mechName, String userName);

    @Message(id = 5162, value = "[%s] Unable to update password for \"%s\"")
    SaslException saslUnableToUpdatePassword(String mechName, String userName);

    @Message(id = 5163, value = "[%s] SASL server timed out")
    SaslException saslServerTimedOut(String mechName);

    @Message(id = 5164, value = "Multiple simultaneous OTP authentications are not allowed")
    SaslException saslMultipleSimultaneousOTPAuthenticationsNotAllowed();

    @Message(id = 5165, value = "OTP re-initialization failed")
    SaslException saslOTPReinitializationFailed(@Cause Throwable cause);

    /* http package */

    @Message(id = 6000, value = "Response code can not be set at this time.")
    IllegalStateException responseCodeNotNow();

    @Message(id = 6001, value = "An incorrectly formatted '%s'header was encountered.")
    HttpAuthenticationException incorrectlyFormattedHeader(String heanderName);

    @Message(id = 6002, value = "An authentication attempt for user '%s' failed validation using mechanism '%s'.")
    String authenticationFailed(String username, String mechanismName);

    /* asn1 package */

    @Message(id = 7001, value = "Unrecognized encoding algorithm")
    ASN1Exception asnUnrecognisedAlgorithm();

    @Message(id = 7002, value = "Invalid general name type")
    ASN1Exception asnInvalidGeneralNameType();

    @Message(id = 7003, value = "Invalid trusted authority type")
    ASN1Exception asnInvalidTrustedAuthorityType();

    @Message(id = 7004, value = "Unexpected ASN.1 tag encountered")
    ASN1Exception asnUnexpectedTag();

    @Message(id = 7005, value = "Unable to read X.509 certificate data")
    ASN1Exception asnUnableToReadCertificateData(@Cause Throwable cause);

    @Message(id = 7006, value = "Invalid general name for URI type")
    ASN1Exception asnInvalidGeneralNameForUriType(@Cause Throwable cause);

    @Message(id = 7007, value = "Invalid general name for IP address type")
    ASN1Exception asnInvalidGeneralNameForIpAddressType();

    @Message(id = 7008, value = "IP address general name cannot be resolved")
    ASN1Exception asnIpAddressGeneralNameCannotBeResolved(@Cause Throwable cause);

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

    /* password package */

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

    @Message(id = 8016, value = "DES crypt password hash must be %d bytes")
    InvalidKeySpecException invalidKeySpecDesCryptPasswordHashMustBeBytes(int bytes);

    @Message(id = 8017, value = "DES crypt password hash must be %d bytes")
    InvalidKeyException invalidKeyDesCryptPasswordHashMustBeBytes(int bytes);

    @Message(id = 8018, value = "Salt must be %d bytes (%d bits)")
    InvalidParameterSpecException invalidParameterSpecSaltMustBeBytesBits(int bytes, int bits);

    @Message(id = 8019, value = "Unsupported parameter spec")
    InvalidParameterSpecException invalidParameterSpecUnsupportedParameterSpec();

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
}
