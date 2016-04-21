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
import java.io.InvalidObjectException;
import java.net.URL;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Permission;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import static org.jboss.logging.Logger.Level.DEBUG;
import static org.jboss.logging.Logger.Level.ERROR;
import static org.jboss.logging.Logger.Level.WARN;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import javax.security.auth.callback.Callback;
import javax.security.jacc.PolicyContextException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.Once;
import org.jboss.logging.annotations.Param;
import org.jboss.modules.ModuleIdentifier;
import org.jboss.modules.ModuleLoadException;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.auth.callback.FastUnsupportedCallbackException;
import org.wildfly.security.auth.permission.RunAsPrincipalPermission;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.AuthorizationCheckException;
import org.wildfly.security.authz.AuthorizationFailureException;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.scram.ScramServerErrorCode;
import org.wildfly.security.mechanism.scram.ScramServerException;
import org.wildfly.security.permission.InvalidPermissionClassException;
import org.wildfly.security.permission.PermissionVerifier;
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
    ElytronMessages tls = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.tls");

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

    @Message(id = 8, value = "The given credential is not supported here")
    IllegalArgumentException credentialNotSupported();

    @Message(id = 9, value = "Invalid name \"%s\"")
    IllegalArgumentException generalInvalidName(String str);

    /* auth package */

    @Message(id = 1000, value = "Authentication name was already set on this context")
    IllegalStateException nameAlreadySet();

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

    @Message(id = 1037, value = "Certificate chain is empty")
    IllegalArgumentException certificateChainIsEmpty();

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

    @Message(id = 1051, value = "Could not resolve password algorithm for credential name \"%s\"")
    InvalidKeyException couldNotResolveAlgorithmByCredentialName(String credentialName);

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

    @Message(id = 1059, value = "Public and private key algorithm names are mismatched")
    IllegalArgumentException mismatchedPublicPrivateKeyAlgorithms();

    @Message(id = 1060, value = "Could not obtain principal")
    RuntimeException couldNotObtainPrincipal();

    @Message(id = 1061, value = "Public key is null")
    IllegalArgumentException publicKeyIsNull();

    @Message(id = 1062, value = "No provider URL has been set")
    IllegalStateException noProviderUrlSet();

    @Message(id = 1063, value = "Private key is null")
    IllegalArgumentException privateKeyIsNull();

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

    @Message(id = 1078, value = "Ldap-backed realm failed to obtain identity \"%s\" from server")
    RuntimeException ldapRealmFailedObtainIdentityFromServer(String identity, @Cause Throwable cause);

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

    @Message(id = 1085, value = "LDAP realm persister does not support given credential type")
    RealmUnavailableException ldapRealmsPersisterNotSupported();

    @Message(id = 1086, value = "Persisting credential %s into Ldap-backed realm failed. Identity dn: \"%s\"")
    RealmUnavailableException ldapRealmCredentialPersistingFailed(String credential, String dn, @Cause Throwable cause);

    @Message(id = 1087, value = "Clearing credentials from Ldap-backed realm failed. Identity dn: \"%s\"")
    RealmUnavailableException ldapRealmCredentialClearingFailed(String dn, @Cause Throwable cause);

    @Message(id = 1088, value = "Attempting to run as \"%s\" authorization operation failed")
    AuthorizationFailureException runAsAuthorizationFailed(@Param Principal principal, Principal targetPrincipal, @Cause Throwable cause);

    @Message(id = 1089, value = "Attempting to run as \"%s\" authorization check failed (permission denied)")
    AuthorizationCheckException unauthorizedRunAs(@Param Principal principal, Principal runAsPrincipal, @Param RunAsPrincipalPermission permission);

    @Message(id = 1090, value = "Unknown LDAP password scheme")
    InvalidKeySpecException unknownLdapPasswordScheme();

    @LogMessage(level = WARN)
    @Message(id = 1091, value = "Post-association peer context action failed")
    void postAssociationFailed(@Cause Throwable cause);

    @Message(id = 1092, value = "Invalid mechanism realm selection \"%s\"")
    IllegalArgumentException invalidMechRealmSelection(String realmName);

    @Message(id = 1093, value = "Mechanism realm was already selected")
    IllegalStateException mechRealmAlreadySelected();

    @LogMessage(level = ERROR)
    @Message(id = 1094, value = "An event handler threw an exception")
    void eventHandlerFailed(@Cause Throwable cause);

    @Message(id = 1095, value = "Unable to create identity")
    RealmUnavailableException unableToCreateIdentity();

    @Message(id = 1096, value = "No such identity")
    RealmUnavailableException noSuchIdentity();

    @Message(id = 1097, value = "Ldap-backed realm failed to delete identity from server")
    RealmUnavailableException ldapRealmFailedDeleteIdentityFromServer(@Cause Throwable cause);

    @Message(id = 1098, value = "Ldap-backed realm failed to create identity on server")
    RealmUnavailableException ldapRealmFailedCreateIdentityOnServer(@Cause Throwable cause);

    @Message(id = 1099, value = "Ldap-backed realm is not configured to allow create new identities (new identity parent and attributes has to be set)")
    RealmUnavailableException ldapRealmNotConfiguredToSupportCreatingIdentities();

    @Message(id = 1100, value = "Ldap-backed realm does not contain mapping to set Elytron attribute \"%s\" of identity \"%s\"")
    RealmUnavailableException ldapRealmCannotSetAttributeWithoutMapping(String attribute, String identity);

    @LogMessage(level = WARN)
    @Message(id = 1101, value = "Ldap-backed realm does not support setting of filtered attribute \"%s\" (identity \"%s\")")
    void ldapRealmDoesNotSupportSettingFilteredAttribute(String attribute, String identity);

    @Message(id = 1102, value = "Ldap-backed realm requires exactly one value of attribute \"%s\" mapped to RDN (identity \"%s\")")
    RealmUnavailableException ldapRealmRequiresExactlyOneRdnAttribute(String attribute, String identity);

    @Message(id = 1103, value = "Ldap-backed realm failed to set attributes of identity \"%s\"")
    RealmUnavailableException ldapRealmAttributesSettingFailed(String identity, @Cause Throwable cause);

    @Message(id = 1104, value = "OAuth2-based realm failed to obtain principal")
    RuntimeException oauth2RealmFailedToObtainPrincipal(@Cause Throwable cause);

    @Message(id = 1105, value = "OAuth2-based realm failed to introspect token")
    RealmUnavailableException oauth2RealmTokenIntrospectionFailed(@Cause Throwable cause);

    @Message(id = 1106, value = "OAuth2-based realm requires a SSLContext when the token introspection endpoint [%s] is using SSL/TLS.")
    IllegalStateException oauth2RealmSSLContextNotSpecified(URL tokenIntrospectionUrl);

    @Message(id = 1107, value = "OAuth2-based realm requires a HostnameVerifier when the token introspection endpoint [%s] is using SSL/TLS.")
    IllegalStateException oauth2RealmHostnameVerifierNotSpecified(URL tokenIntrospectionUrl);

    @Message(id = 1108, value = "Ldap-backed realm identity search failed")
    RuntimeException ldapRealmIdentitySearchFailed(@Cause Throwable cause);

    @Message(id = 1109, value = "Ldap-backed realm is not configured to allow iterate over identities (iterator filter has to be set)")
    RealmUnavailableException ldapRealmNotConfiguredToSupportIteratingOverIdentities();

    @Message(id = 1110, value = "Peer identities were already set on this context")
    IllegalStateException peerIdentitiesAlreadySet();

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

    // id = 2012 KeyStoreException "Secret keys not supported"

    // id = 2013 KeyStoreException "Direct key storage not supported"

    // id = 2014 KeyStoreException "Only password storage is supported"

    @Message(id = 2012, value = "An empty alias filter was supplied")
    IllegalArgumentException emptyFilter();

    @Message(id = 2013, value = "Filter is missing '+' or '-' at offest %d")
    IllegalArgumentException missingPlusMinusAt(int position);

    @Message(id = 2014, value = "Invalid first word '%s', must be one of ALL/NONE")
    IllegalArgumentException invalidFirstWord(String firstWord);

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

    @Message(id = 3010, value = "Malformed PEM content at offset %d")
    IllegalArgumentException malformedPemContent(int offset);

    @Message(id = 3011, value = "Invalid PEM type (expected \"%s\", got \"%s\"")
    IllegalArgumentException invalidPemType(String expected, String actual);

    @Message(id = 3012, value = "Certificate parse error")
    IllegalArgumentException certificateParseError(@Cause CertificateException cause);

    @Message(id = 3013, value = "Permission collection must be read-only")
    SecurityException permissionCollectionMustBeReadOnly();

    @Message(id = 3014, value = "Invalid character found in name \"%s\" at offset %d")
    IllegalArgumentException invalidPermissionName(String name, int offset);

    @Message(id = 3015, value = "Could not load permission class \"%s\"")
    InvalidPermissionClassException permissionClassMissing(String className, @Cause ClassNotFoundException cause);

    @Message(id = 3016, value = "Could not instantiate permission class \"%s\"")
    InvalidPermissionClassException permissionInstantiation(String className, @Cause Throwable cause);

    @Message(id = 3017, value = "No valid permission constructor found on class \"%s\"")
    InvalidPermissionClassException noPermissionConstructor(String className);

    @Message(id = 3018, value = "Cannot add permissions to a read-only permission collection")
    SecurityException readOnlyPermissionCollection();

    @Message(id = 3019, value = "Failure to deserialize object: field \"%s\" is null")
    InvalidObjectException invalidObjectNull(String fieldName);

    @Message(id = 3020, value = "Expected empty actions string, got \"%s\"")
    IllegalArgumentException expectedEmptyActions(String actions);

    @Message(id = 3021, value = "Invalid permission type; expected %s, got %s")
    IllegalArgumentException invalidPermissionType(Class<? extends Permission> expected, Permission actual);

    @Message(id = 3022, value = "Permission check failed: %s is not implied by %s")
    SecurityException permissionCheckFailed(Permission permission, PermissionVerifier permissionVerifier);

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

    @Message(id = 4006, value = "No context for SSL connection")
    SSLHandshakeException noContextForSslConnection();

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

    @Message(id = 4024, value = "Invalid client mode, expected %s, got %s")
    IllegalArgumentException invalidClientMode(boolean expectedMode, boolean givenMode);

    /* mechanism package */

    @Message(id = 5001, value = "[%s] Authentication mechanism exchange received a message after authentication was already complete")
    AuthenticationMechanismException mechMessageAfterComplete(String mechName);

    @Message(id = 5002, value = "[%s] Authentication mechanism user name contains an invalid or disallowed character")
    AuthenticationMechanismException mechUserNameContainsInvalidCharacter(String mechName);

    // 5003

    @Message(id = 5004, value = "[%s] Authentication mechanism authorization failed")
    AuthenticationMechanismException mechAuthorizationFailed(String mechName, @Cause Throwable cause);

    @Message(id = 5005, value = "[%s] Authentication mechanism authentication is not yet complete")
    IllegalStateException mechAuthenticationNotComplete(String mechName);

    @Message(id = 5006, value = "[%s] Authentication mechanism does not support security layer (wrapping/unwrapping)")
    AuthenticationMechanismException mechNoSecurityLayer(String mechName);

    @Message(id = 5007, value = "[%s] Invalid authentication mechanism negotiation message received")
    AuthenticationMechanismException mechInvalidMessageReceived(String mechName);

    @Message(id = 5008, value = "[%s] No authentication mechanism login name was given")
    AuthenticationMechanismException mechNoLoginNameGiven(String mechName);

    @Message(id = 5009, value = "[%s] No authentication mechanism password was given")
    AuthenticationMechanismException mechNoPasswordGiven(String mechName);

    @Message(id = 5010, value = "[%s] Authentication mechanism authentication failed due to one or more malformed fields")
    AuthenticationMechanismException mechMalformedFields(String mechName, @Cause IllegalArgumentException ex);

    @Message(id = 5011, value = "[%s] Authentication mechanism message is too long")
    AuthenticationMechanismException mechMessageTooLong(String mechName);

    @Message(id = 5012, value = "[%s] Authentication mechanism server-side authentication failed")
    AuthenticationMechanismException mechServerSideAuthenticationFailed(String mechName, @Cause Exception e);

    @Message(id = 5013, value = "[%s] Authentication mechanism password not verified")
    AuthenticationMechanismException mechPasswordNotVerified(String mechName);

    @Message(id = 5014, value = "[%s] Authentication mechanism authorization failed: \"%s\" running as \"%s\"")
    AuthenticationMechanismException mechAuthorizationFailed(String mechName, String userName, String authorizationId);

    @Message(id = 5015, value = "Unexpected character U+%04x at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnexpectedChar(int codePoint, int offset, String string);

    @Message(id = 5016, value = "Unrecognized token \"%s\" in mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnknownToken(String word, String string);

    @Message(id = 5017, value = "Token \"%s\" not allowed at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorTokenNotAllowed(String token, int offset, String string);

    @Message(id = 5018, value = "[%s] Channel binding data changed")
    AuthenticationMechanismException mechChannelBindingChanged(String mechName);

    // 5019

    // 5020

    // 5021

    @Message(id = 5022, value = "[%s] Initial challenge must be empty")
    AuthenticationMechanismException mechInitialChallengeMustBeEmpty(String mechName);

    @Message(id = 5023, value = "[%s] Unable to set channel binding")
    AuthenticationMechanismException mechUnableToSetChannelBinding(String mechName, @Cause Exception e);

    @Message(id = 5024, value = "Failed to determine channel binding status")
    AuthenticationMechanismException mechFailedToDetermineChannelBindingStatus(@Cause Exception e);

    @Message(id = 5025, value = "[%s] Mutual authentication not enabled")
    AuthenticationMechanismException mechMutualAuthenticationNotEnabled(String mechName);

    @Message(id = 5026, value = "[%s] Unable to map SASL mechanism name to a GSS-API OID")
    AuthenticationMechanismException mechMechanismToOidMappingFailed(String mechName, @Cause Exception e);

    @Message(id = 5027, value = "[%s] Unable to dispose of GSSContext")
    AuthenticationMechanismException mechUnableToDisposeGssContext(String mechName, @Cause Exception e);

    @Message(id = 5028, value = "[%s] Unable to create name for acceptor")
    AuthenticationMechanismException mechUnableToCreateNameForAcceptor(String mechName, @Cause Exception e);

    @Message(id = 5029, value = "[%s] Unable to create GSSContext")
    AuthenticationMechanismException mechUnableToCreateGssContext(String mechName, @Cause Exception e);

    @Message(id = 5030, value = "[%s] Unable to set GSSContext request flags")
    AuthenticationMechanismException mechUnableToSetGssContextRequestFlags(String mechName, @Cause Exception e);

    @Message(id = 5031, value = "[%s] Unable to accept SASL client message")
    AuthenticationMechanismException mechUnableToAcceptClientMessage(String mechName, @Cause Exception e);

    @Message(id = 5032, value = "[%s] GSS-API mechanism mismatch between SASL client and server")
    AuthenticationMechanismException mechGssApiMechanismMismatch(String mechName);

    @Message(id = 5033, value = "[%s] Channel binding not supported for this SASL mechanism")
    AuthenticationMechanismException mechChannelBindingNotSupported(String mechName);

    @Message(id = 5034, value = "[%s] Channel binding type mismatch between SASL client and server")
    AuthenticationMechanismException mechChannelBindingTypeMismatch(String mechName);

    @Message(id = 5035, value = "[%s] Channel binding not provided by client")
    AuthenticationMechanismException mechChannelBindingNotProvided(String mechName);

    @Message(id = 5036, value = "[%s] Unable to determine peer name")
    AuthenticationMechanismException mechUnableToDeterminePeerName(String mechName, @Cause Exception e);

    @Message(id = 5037, value = "[%s] Authentication mechanism client refuses to initiate authentication")
    AuthenticationMechanismException mechClientRefusesToInitiateAuthentication(String mechName);

    @Message(id = 5038, value = "[%s] Nonces do not match")
    AuthenticationMechanismException mechNoncesDoNotMatch(String mechName);

    @Message(id = 5039, value = "[%s] Server nonce is too short")
    AuthenticationMechanismException mechServerNonceIsTooShort(String mechName);

    @Message(id = 5040, value = "[%s] Iteration count %d is below the minimum of %d")
    AuthenticationMechanismException mechIterationCountIsTooLow(String mechName, int iterationCount, int minimumIterationCount);

    @Message(id = 5041, value = "[%s] Iteration count %d is above the maximum of %d")
    AuthenticationMechanismException mechIterationCountIsTooHigh(String mechName, int iterationCount, int maximumIterationCount);

    @Message(id = 5042, value = "[%s] Extensions unsupported")
    AuthenticationMechanismException mechExtensionsUnsupported(String mechName);

    @Message(id = 5043, value = "[%s] Invalid server message")
    AuthenticationMechanismException mechInvalidServerMessage(String mechName);

    @Message(id = 5044, value = "[%s] Invalid server message")
    AuthenticationMechanismException mechInvalidServerMessageWithCause(String mechName, @Cause Throwable cause);

    @Message(id = 5045, value = "[%s] Invalid client message")
    AuthenticationMechanismException mechInvalidClientMessage(String mechName);

    @Message(id = 5046, value = "[%s] Invalid client message")
    AuthenticationMechanismException mechInvalidClientMessageWithCause(String mechName, @Cause Throwable cause);

    @Message(id = 5047, value = "[%s] Authentication mechanism message is for mismatched mechanism \"%s\"")
    AuthenticationMechanismException mechUnmatchedMechanism(String mechName, String otherMechName);

    @Message(id = 5048, value = "[%s] Server rejected authentication")
    AuthenticationMechanismException mechServerRejectedAuthentication(String mechName);

    @Message(id = 5049, value = "[%s] Server authenticity cannot be verified")
    AuthenticationMechanismException mechServerAuthenticityCannotBeVerified(String mechName);

    @Message(id = 5050, value = "[%s] Callback handler does not support user name")
    AuthenticationMechanismException mechCallbackHandlerDoesNotSupportUserName(String mechName, @Cause Throwable cause);

    @Message(id = 5051, value = "[%s] Callback handler does not support credential acquisition")
    AuthenticationMechanismException mechCallbackHandlerDoesNotSupportCredentialAcquisition(String mechName, @Cause Throwable cause);

    @Message(id = 5052, value = "[%s] Callback handler does not support authorization")
    AuthenticationMechanismException mechAuthorizationUnsupported(String mechName, @Cause Throwable cause);

    @Message(id = 5053, value = "[%s] Callback handler failed for unknown reason")
    AuthenticationMechanismException mechCallbackHandlerFailedForUnknownReason(String mechName, @Cause Throwable cause);

    @Message(id = 5054, value = "[%s] Salt must be specified")
    AuthenticationMechanismException mechSaltMustBeSpecified(String mechName);

    @Message(id = 5055, value = "[%s] Authentication rejected (invalid proof)")
    AuthenticationMechanismException mechAuthenticationRejectedInvalidProof(String mechName);

    @Message(id = 5056, value = "[%s] Client sent extra message")
    AuthenticationMechanismException mechClientSentExtraMessage(String mechName);

    @Message(id = 5057, value = "[%s] Server sent extra message")
    AuthenticationMechanismException mechServerSentExtraMessage(String mechName);

    @Message(id = 5058, value = "[%s] Authentication failed")
    AuthenticationMechanismException mechAuthenticationFailed(String mechName);

    @Message(id = 5059, value = "[%s] Invalid MAC initialization key")
    AuthenticationMechanismException mechInvalidMacInitializationKey(String mechName);

    @Message(id = 5060, value = "Empty number")
    NumberFormatException emptyNumber();

    @Message(id = 5061, value = "Invalid numeric character")
    NumberFormatException invalidNumericCharacter();

    @Message(id = 5062, value = "Too big number")
    NumberFormatException tooBigNumber();

    @Message(id = 5063, value = "[%s] Cannot get clear password from two way password")
    AuthenticationMechanismException mechCannotGetTwoWayPasswordChars(String mechName, @Cause Throwable cause);

    @Message(id = 5064, value = "[%s] Hashing algorithm not supported")
    AuthenticationMechanismException mechMacAlgorithmNotSupported(String mechName, @Cause Throwable cause);

    @Message(id = 5065, value = "[%s] keyword cannot be empty")
    AuthenticationMechanismException mechKeywordCannotBeEmpty(String mechName);

    @Message(id = 5066, value = "[%s] No value found for keyword: %s")
    AuthenticationMechanismException mechNoValueFoundForKeyword(String mechName, String keyword);

    @Message(id = 5067, value = "[%s] '=' expected after keyword: %s")
    AuthenticationMechanismException mechKeywordNotFollowedByEqual(String mechName, String keyword);

    @Message(id = 5068, value = "[%s] Unmatched quote found for value: %s")
    AuthenticationMechanismException mechUnmatchedQuoteFoundForValue(String mechName, String value);

    @Message(id = 5069, value = "[%s] Expecting comma or linear whitespace after quoted string: %s")
    AuthenticationMechanismException mechExpectingCommaOrLinearWhitespaceAfterQuoted(String mechName, String value);

    @Message(id = 5070, value = "[%s] MessageType must equal to %d, but it is %d")
    AuthenticationMechanismException mechMessageTypeMustEqual(String mechName, int expected, int actual);

    @Message(id = 5071, value = "[%s] Bad sequence number while unwrapping: expected %d, but %d received")
    AuthenticationMechanismException mechBadSequenceNumberWhileUnwrapping(String mechName, int expected, int actual);

    @Message(id = 5072, value = "[%s] Problem during crypt")
    AuthenticationMechanismException mechProblemDuringCrypt(String mechName, @Cause Throwable cause);

    @Message(id = 5073, value = "[%s] Problem during decrypt")
    AuthenticationMechanismException mechProblemDuringDecrypt(String mechName, @Cause Throwable cause);

    @Message(id = 5074, value = "[%s] Unknown cipher \"%s\"")
    AuthenticationMechanismException mechUnknownCipher(String mechName, String cipher);

    @Message(id = 5075, value = "[%s] Authorization ID changed unexpectedly")
    AuthenticationMechanismException mechAuthorizationIdChanged(String mechName);

    @Message(id = 5076, value = "[%s] Problem getting required cipher. Check your transformation mapper settings.")
    AuthenticationMechanismException mechProblemGettingRequiredCipher(String mechName, @Cause Throwable cause);

    @Message(id = 5077, value = "[%s] No common protection layer between client and server")
    AuthenticationMechanismException mechNoCommonProtectionLayer(String mechName);

    @Message(id = 5078, value = "[%s] No common cipher between client and server")
    AuthenticationMechanismException mechNoCommonCipher(String mechName);

    @Message(id = 5079, value = "[%s] No ciphers offered by server")
    AuthenticationMechanismException mechNoCiphersOfferedByServer(String mechName);

    @Message(id = 5080, value = "[%s] Callback handler not provided user name")
    AuthenticationMechanismException mechNotProvidedUserName(String mechName);

    @Message(id = 5081, value = "[%s] Callback handler not provided pre-digested password")
    AuthenticationMechanismException mechNotProvidedPreDigested(String mechName);

    @Message(id = 5082, value = "[%s] Callback handler not provided clear password")
    AuthenticationMechanismException mechNotProvidedClearPassword(String mechName);

    @Message(id = 5083, value = "[%s] Missing \"%s\" directive")
    AuthenticationMechanismException mechMissingDirective(String mechName, String directive);

    @Message(id = 5084, value = "[%s] nonce-count must equal to %d, but it is %d")
    AuthenticationMechanismException mechNonceCountMustEqual(String mechName, int expected, int actual);

    @Message(id = 5085, value = "[%s] Server is set to not support %s charset")
    AuthenticationMechanismException mechUnsupportedCharset(String mechName, String charset);

    @Message(id = 5086, value = "[%s] Charset can be only \"utf-8\" or unspecified (to use ISO 8859-1)")
    AuthenticationMechanismException mechUnknownCharset(String mechName);

    @Message(id = 5087, value = "[%s] Client selected realm not offered by server (%s)")
    AuthenticationMechanismException mechDisallowedClientRealm(String mechName, String clientRealm);

    @Message(id = 5088, value = "[%s] Mismatched digest-uri \"%s\" Expected: \"%s\"")
    AuthenticationMechanismException mechMismatchedWrongDigestUri(String mechName, String actual, String expected);

    @Message(id = 5089, value = "[%s] Unexpected qop value: \"%s\"")
    AuthenticationMechanismException mechUnexpectedQop(String mechName, String qop);

    @Message(id = 5090, value = "[%s] Wrapping is not configured")
    IllegalStateException wrappingNotConfigured(String mechName);

    @Message(id = 5091, value = "[%s] Authentication name string is too long")
    AuthenticationMechanismException mechAuthenticationNameTooLong(String mechName);

    @Message(id = 5092, value = "[%s] Authentication name is empty")
    AuthenticationMechanismException mechAuthenticationNameIsEmpty(String mechName);

    @Message(id = 5093, value = "[%s] Authorization for anonymous access is denied")
    AuthenticationMechanismException mechAnonymousAuthorizationDenied(String mechName);

    @Message(id = 5094, value = "Required padded length (%d) is less than length of conversion result (%d)")
    IllegalArgumentException requiredNegativePadding(int totalLength, int hexLength);

    @Message(id = 5095, value = "Invalid key provided for Digest HMAC computing")
    AuthenticationMechanismException mechInvalidKeyForDigestHMAC();

    @Message(id = 5096, value = "Unable to read certificate from URL \"%s\"")
    IOException asnUnableToReadCertificateFromUrl(String url, @Cause Throwable cause);

    @Message(id = 5097, value = "Unable to determine subject name from X.509 certificate")
    IllegalStateException unableToDetermineSubjectName(@Cause Throwable cause);

    @Message(id = 5098, value = "[%s] Unable to verify client signature")
    AuthenticationMechanismException mechUnableToVerifyClientSignature(String mechName, @Cause Throwable cause);

    @Message(id = 5099, value = "[%s] Unable to verify server signature")
    AuthenticationMechanismException mechUnableToVerifyServerSignature(String mechName, @Cause Throwable cause);

    @Message(id = 5100, value = "[%s] Unable to obtain other side certificate from URL \"%s\"")
    AuthenticationMechanismException mechUnableToObtainServerCertificate(String mechName, String url, @Cause Throwable cause);

    @Message(id = 5101, value = "[%s] Callback handler not provided URL of server certificate")
    AuthenticationMechanismException mechCallbackHandlerNotProvidedServerCertificate(String mechName);

    @Message(id = 5102, value = "[%s] Callback handler not provided URL of client certificate")
    AuthenticationMechanismException mechCallbackHandlerNotProvidedClientCertificate(String mechName);

    @Message(id = 5103, value = "[%s] Server identifier mismatch")
    AuthenticationMechanismException mechServerIdentifierMismatch(String mechName);

    @Message(id = 5104, value = "[%s] Client identifier mismatch")
    AuthenticationMechanismException mechClientIdentifierMismatch(String mechName);

    @Message(id = 5105, value = "[%s] Unable to determine client name")
    AuthenticationMechanismException mechUnableToDetermineClientName(String mechName, @Cause Throwable cause);

    @Message(id = 5106, value = "[%s] Callback handler not provided private key")
    AuthenticationMechanismException mechCallbackHandlerNotProvidedPrivateKey(String mechName);

    @Message(id = 5107, value = "[%s] Unable to create signature")
    AuthenticationMechanismException mechUnableToCreateSignature(String mechName, @Cause Throwable cause);

    @Message(id = 5108, value = "[%s] Unable to create response token")
    AuthenticationMechanismException mechUnableToCreateResponseToken(String mechName, @Cause Throwable cause);

    @Message(id = 5109, value = "[%s] Unable to create response token")
    AuthenticationMechanismException mechUnableToCreateResponseTokenWithCause(String mechName, @Cause Throwable cause);

    @Message(id = 5110, value = "Invalid value for trusted authority type; expected a value between 0 and 4 (inclusive)")
    IllegalArgumentException invalidValueForTrustedAuthorityType();

    @Message(id = 5111, value = "Invalid value for a general name type; expected a value between 0 and 8 (inclusive)")
    IllegalArgumentException invalidValueForGeneralNameType();

    @Message(id = 5112, value = "Getting authentication mechanisms supported by GSS-API failed")
    AuthenticationMechanismException mechGettingSupportedMechanismsFailed(@Cause Throwable cause);

    @Message(id = 5113, value = "Unable to initialize OID of Kerberos V5")
    RuntimeException unableToInitialiseOid(@Cause Throwable cause);

    @Message(id = 5114, value = "[%s] Receive buffer requested '%d' is greater than supported maximum '%d'")
    AuthenticationMechanismException mechReceiveBufferIsGreaterThanMaximum(String mechName, int requested, int maximum);

    @Message(id = 5115, value = "[%s] Unable to wrap message")
    AuthenticationMechanismException mechUnableToWrapMessage(String mechName, @Cause Throwable cause);

    @Message(id = 5116, value = "[%s] Unable to unwrap message")
    AuthenticationMechanismException mechUnableToUnwrapMessage(String mechName, @Cause Throwable cause);

    @Message(id = 5117, value = "[%s] Unable to unwrap security layer negotiation message")
    AuthenticationMechanismException mechUnableToUnwrapSecurityLayerNegotiationMessage(String mechName, @Cause Throwable cause);

    @Message(id = 5118, value = "[%s] Invalid message of length %d on unwrapping")
    AuthenticationMechanismException mechInvalidMessageOnUnwrapping(String mechName, int length);

    @Message(id = 5119, value = "[%s] Negotiated mechanism was not Kerberos V5")
    AuthenticationMechanismException mechNegotiatedMechanismWasNotKerberosV5(String mechName);

    @Message(id = 5120, value = "[%s] Insufficient levels of protection available for supported security layers")
    AuthenticationMechanismException mechInsufficientQopsAvailable(String mechName);

    @Message(id = 5121, value = "[%s] Unable to generate security layer challenge")
    AuthenticationMechanismException mechUnableToGenerateChallenge(String mechName, @Cause Throwable cause);

    @Message(id = 5122, value = "[%s] Client selected a security layer that was not offered by server")
    AuthenticationMechanismException mechSelectedUnofferedQop(String mechName);

    @Message(id = 5123, value = "[%s] No security layer selected but message length received")
    AuthenticationMechanismException mechNoSecurityLayerButLengthReceived(String mechName);

    @Message(id = 5124, value = "[%s] Unable to get maximum size of message before wrap")
    AuthenticationMechanismException mechUnableToGetMaximumSizeOfMessage(String mechName, @Cause Throwable cause);

    @Message(id = 5125, value = "[%s] Unable to handle response from server")
    AuthenticationMechanismException mechUnableToHandleResponseFromServer(String mechName, @Cause Throwable cause);

    @Message(id = 5126, value = "[%s] Bad length of message for negotiating security layer")
    AuthenticationMechanismException mechBadLengthOfMessageForNegotiatingSecurityLayer(String mechName);

    @Message(id = 5127, value = "[%s] No security layer supported by server but maximum message size received: \"%d\"")
    AuthenticationMechanismException mechReceivedMaxMessageSizeWhenNoSecurityLayer(String mechName, int length);

    @Message(id = 5128, value = "[%s] Failed to read challenge file")
    AuthenticationMechanismException mechFailedToReadChallengeFile(String mechName, @Cause Throwable cause);

    @Message(id = 5129, value = "[%s] Failed to create challenge file")
    AuthenticationMechanismException mechFailedToCreateChallengeFile(String mechName, @Cause Throwable cause);

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

    @Message(id = 5149, value = "[%s] Authentication name changed unexpectedly")
    AuthenticationMechanismException mechAuthenticationNameChanged(String mechName);

    @Message(id = 5150, value = "[%s] Authentication mechanism authorization ID is too long")
    AuthenticationMechanismException mechAuthorizationIdTooLong(String mechName);

    @Message(id = 5151, value = "Invalid OTP algorithm \"%s\"")
    AuthenticationMechanismException mechInvalidOTPAlgorithm(String algorithm);

    @Message(id = 5152, value = "Invalid OTP response type")
    AuthenticationMechanismException mechInvalidOTPResponseType();

    @Message(id = 5153, value = "[%s] Incorrect parity in SASL client message")
    AuthenticationMechanismException mechIncorrectParity(String mechName);

    @Message(id = 5154, value = "[%s] Invalid character in seed")
    AuthenticationMechanismException mechInvalidCharacterInSeed(String mechName);

    @Message(id = 5155, value = "Invalid OTP seed, must be between 1 and 16 characters long")
    AuthenticationMechanismException mechInvalidOTPSeed();

    @Message(id = 5156, value = "Invalid OTP pass phrase, must be between 10 and 63 characters long")
    AuthenticationMechanismException mechInvalidOTPPassPhrase();

    @Message(id = 5157, value = "Invalid OTP sequence number")
    AuthenticationMechanismException mechInvalidOTPSequenceNumber();

    @Message(id = 5158, value = "Invalid OTP")
    AuthenticationMechanismException mechInvalidOTP();

    @Message(id = 5159, value = "OTP pass phrase and seed must not match")
    AuthenticationMechanismException mechOTPPassPhraseAndSeedMustNotMatch();

    @Message(id = 5160, value = "Invalid OTP alternate dictionary")
    AuthenticationMechanismException mechInvalidOTPAlternateDictionary();

    @Message(id = 5161, value = "[%s] Unable to retrieve password for \"%s\"")
    AuthenticationMechanismException mechUnableToRetrievePassword(String mechName, String userName);

    @Message(id = 5162, value = "[%s] Unable to update password for \"%s\"")
    AuthenticationMechanismException mechUnableToUpdatePassword(String mechName, String userName);

    @Message(id = 5163, value = "[%s] Authentication mechanism server timed out")
    AuthenticationMechanismException mechServerTimedOut(String mechName);

    @Message(id = 5164, value = "Multiple simultaneous OTP authentications are not allowed")
    AuthenticationMechanismException mechMultipleSimultaneousOTPAuthenticationsNotAllowed();

    @Message(id = 5165, value = "OTP re-initialization failed")
    AuthenticationMechanismException mechOTPReinitializationFailed(@Cause Throwable cause);

    @Message(id = 5166, value = "[%s] Server rejected authentication")
    ScramServerException scramServerRejectedAuthentication(String mechName, @Param ScramServerErrorCode errorCode);

    /* http package */

    @Message(id = 6000, value = "Response code can not be set at this time.")
    IllegalStateException responseCodeNotNow();

    @Message(id = 6001, value = "An incorrectly formatted '%s'header was encountered.")
    String incorrectlyFormattedHeader(String heanderName);

    @Message(id = 6002, value = "An authentication attempt for user '%s' failed validation using mechanism '%s'.")
    String authenticationFailed(String username, String mechanismName);

    @Message(id = 6003, value = "An authentication attempt failed validation using mechanism '%s'.")
    String authenticationFailed(String mechanismName);

    @Message(id = 6004, value = "Session management not supported. This is probably because no HttpSessionSpi was implemented for the underlying container.")
    IllegalStateException httpSessionNotSupported();

    @Message(id = 6005, value= "Attachments are not supported on this scope.")
    UnsupportedOperationException noAttachmentSupport();

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

    /* authz package */

    @LogMessage(level = ERROR)
    @Message(id = 8030, value = "Failed to check permissions for protection domain [%s] and permission [%s].")
    void authzFailedToCheckPermission(ProtectionDomain domain, Permission permission, @Cause Throwable cause);

    @Message(id = 8031, value = "Invalid state [%s] for operation.")
    UnsupportedOperationException authzInvalidStateForOperation(String actualState);

    @Message(id = 8032, value = "Can't link policy configuration [%s] to itself.")
    IllegalArgumentException authzLinkSamePolicyConfiguration(String contextID);

    @Message(id = 8033, value = "ContextID not set. Check if the context id was set using PolicyContext.setContextID.")
    IllegalStateException authzContextIdentifierNotSet();

    @Message(id = 8034, value = "Invalid policy context identifier [%s].")
    IllegalArgumentException authzInvalidPolicyContextIdentifier(String contextID);

    @Message(id = 8035, value = "Could not obtain PolicyConfiguration for contextID [%s].")
    PolicyContextException authzUnableToObtainPolicyConfiguration(String contextId, @Cause Throwable cause);

    @Message(id = 8036, value = "Policy configuration with contextID [%s] is not in service state.")
    IllegalStateException authzPolicyConfigurationNotInService(String contextID);

    @LogMessage(level = ERROR)
    @Message(id = 8037, value = "Could not obtain dynamic permissions.")
    void authzFailedGetDynamicPermissions(@Cause Throwable cause);

    @LogMessage(level = DEBUG)
    @Message(id = 8038, value = "Could not obtain authorized identity.")
    void authzCouldNotObtainSecurityIdentity(@Cause Throwable cause);

    @Once
    @LogMessage(level = WARN)
    @Message(id = 8039, value = "Calling any of the Policy.getPermissions() methods is not supported; please see the "
        + "Java Authorization Contract for Containers (JACC) specification (section \"1.4 Requirements\", item 1) and "
        + "the Java SE API specification for the Policy.getPermissions() methods for more information.  Instead, use "
        + "the Policy.implies() method for authorization checking.")
    void getPermissionsNotSupported();

    /* credential.store. package */

    @Message(id = 9501, value = "Credential store '%s' has to be initialized before the first usage")
    CredentialStoreException credentialStoreNotInitialized(String name);

    @Message(id = 9502, value = "Reloadable credential store '%s' has to be read only, change settings and restart vault service")
    CredentialStoreException reloadablecredentialStoreIsReadOnly(String name);

    @Message(id = 9503, value = "credential alias '%s' cannot be found in the store '%s'")
    CredentialStoreException credentialAliasNotFoundNotFound(String credentialAlias, String name);

    @Message(id = 9504, value = "Cannot write storage file '%s' for the store '%s'")
    CredentialStoreException cannotWriteStorageFie(String fileName, String name);

    @Message(id = 9505, value = "Following configuration attributes are not supported by KeystorePasswordStore named '%s' : '%s'")
    CredentialStoreException unsupportedPasswordStorageConfigurationAttributes(String vaultName, String attributes);

    @Message(id = 9506, value = "Cannot read credential storage file '%s' for the store named '%s'")
    CredentialStoreException cannotReadVaultStorage(String fileName, String vaultName, @Cause Exception cause);

    @Message(id = 9507, value = "Credential store '%s' doesn't contain admin key under alias '%s'")
    CredentialStoreException storeAdminKeyNotPresent(String name, String alias);

    @Message(id = 9508, value = "Method '%s' not implemented by credential store '%s'")
    CredentialStoreException methodNotImplemented(String methodName, String storeName);

    @Message(id = 9509, value = "Problem executing password command by credential store '%s'")
    CredentialStoreException passwordCommandExecutionProblem(String storeName, @Cause Throwable cause);

    @Message(id = 9510, value = "Credential type '%s' not supported by credential store '%s'")
    CredentialStoreException credentialTypeNotSupported(String credentialType, String storeName);

    @Message(id = 9511, value = "Password cache for external commands not supported")
    CredentialStoreException cacheForExternalCommandsNotSupported();

    @LogMessage
    @Message(id = 9512, value = "Wrong Base64 encoded string used. Falling back to '%s'")
    void warnWrongBase64EncodedString(String base64);
}
