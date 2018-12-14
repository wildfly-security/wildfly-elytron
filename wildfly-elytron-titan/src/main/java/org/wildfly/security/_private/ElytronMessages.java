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
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.client.config.ConfigurationXMLStreamReader;
import org.wildfly.client.config.XMLLocation;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.AuthorizationFailureException;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.permission.InvalidPermissionClassException;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages audit = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.audit");
    ElytronMessages xmlLog = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.xml");
    ElytronMessages tls = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.tls");
    ElytronMessages sasl = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl");
    ElytronMessages saslAnonymous = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.anonymous");
    ElytronMessages saslDigest = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.digest");
    ElytronMessages saslEntity = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.entity");
    ElytronMessages saslExternal = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.external");
    ElytronMessages saslGs2 = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.gs2");
    ElytronMessages saslGssapi = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.gssapi");
    ElytronMessages saslLocal = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.local");
    ElytronMessages saslOAuth2 = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.oauth2");
    ElytronMessages saslOTP = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.otp");
    ElytronMessages saslPlain = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.plain");
    ElytronMessages saslScram = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.scram");
    ElytronMessages httpSpnego = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.spnego");
    ElytronMessages httpClientCert = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.cert");
    ElytronMessages httpDigest = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.digest");
    ElytronMessages httpUserPass = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.password");
    ElytronMessages httpForm = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.form");
    ElytronMessages httpBearer = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.bearer");
    ElytronMessages httpBasic = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.basic");
    ElytronMessages acme = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.x500.cert.acme");

    @LogMessage
    @Message(id = 1, value = "WildFly Elytron version %s")
    void logVersion(String versionString);

    // Used both for LDAP Realm and wildfly-elyton-credential
    @Message(id = 2, value = "Parameter %s is empty")
    IllegalArgumentException emptyParameter(String parameter);

    // Multi Use
    @Message(id = 3, value = "This builder has already been built")
    IllegalStateException builderAlreadyBuilt();

    // Used both for LDAP Realm and wildfly-elyton-credential
    @Message(id = 4, value = "Unrecognized algorithm \"%s\"")
    IllegalArgumentException unrecognizedAlgorithm(String algorithm);

//    @Message(id = 5, value = "Cannot instantiate self-referential factory")
//    IllegalStateException cannotInstantiateSelfReferentialFactory();

//    @Message(id = 6, value = "Unexpected trailing garbage in X.500 principal")
//    IllegalArgumentException unexpectedTrailingGarbageInX500principal();

    // Used both for LDAP Realm and mechanisms
    @LogMessage(level = WARN)
    @Message(id = 7, value = "Credential destroying failed")
    void credentialDestroyingFailed(@Cause Throwable cause);

//    @Message(id = 8, value = "The given credential is not supported here")
//    IllegalArgumentException credentialNotSupported();

//    @Message(id = 9, value = "Invalid name \"%s\"")
//    IllegalArgumentException generalInvalidName(String str);

    // @Message(id = 10, value = "Identity locator field \"%s\" is not set")
    // IllegalStateException locatorFieldNotSet(String fieldName);

    @Message(id = 11, value = "Unable to create service for '%s.%s' ")
    NoSuchAlgorithmException noSuchAlgorithmCreateService(String serviceType, String algorithm, @Cause Throwable cause);

//    @Message(id = 12, value = "Unable to load OIDs database from properties file")
//    IllegalStateException unableToLoadOidsFromPropertiesFile(@Cause Throwable cause);

    /* auth package */

//    @Message(id = 1000, value = "Authentication name was already set on this context")
//    IllegalStateException nameAlreadySet();

    @Message(id = 1001, value = "No module found for identifier \"%s\"")
    ConfigXMLParseException xmlNoModuleFound(@Param XMLStreamReader reader, @Cause Exception e, String moduleIdentifier);

    @Message(id = 1002, value = "Invalid port number \"%s\" specified for attribute \"%s\" of element \"%s\"; expected a numerical value between 1 and 65535 (inclusive)")
    ConfigXMLParseException xmlInvalidPortNumber(@Param XMLStreamReader reader, String attributeValue, String attributeName, QName elementName);

//    @Message(id = 1003, value = "No authentication is in progress")
//    IllegalStateException noAuthenticationInProgress();

    // @Message(id = 1004, value = "Authentication already complete on this context")
    // IllegalStateException authenticationAlreadyComplete();

//    @Message(id = 1005, value = "Realm map does not contain mapping for default realm '%s'")
//    IllegalArgumentException realmMapDoesNotContainDefault(String defaultRealm);

    @Message(id = 1006, value = "No realm name found in users property file - non-plain-text users file must contain \"#$REALM_NAME=RealmName$\" line")
    RealmUnavailableException noRealmFoundInProperties();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 1007, value = "JAAS authentication failed for principal %s")
    void debugJAASAuthenticationFailure(Principal principal, @Cause Throwable cause);

    @Message(id = 1008, value = "Failed to create login context")
    RealmUnavailableException failedToCreateLoginContext(@Cause Throwable cause);

    @Message(id = 1009, value = "Failed to instantiate custom CallbackHandler")
    RealmUnavailableException failedToInstantiateCustomHandler(@Cause Throwable cause);

    // @Message(id = 1010, value = "Credential cannot be converted to a password")
    // FastUnsupportedCallbackException failedToConvertCredentialToPassword(@Param Callback callback);

    // @Message(id = 1011, value = "Unrecognized principal type for %s")
    // IllegalArgumentException unrecognizedPrincipalType(Principal principal);

    @Message(id = 1012, value = "Filesystem-backed realm unexpectedly failed to open path \"%s\" for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmFailedToOpen(Path path, String finalName, @Cause IOException cause);

    @Message(id = 1013, value = "Filesystem-backed realm unexpectedly failed to read path \"%s\" for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmFailedToRead(Path path, String finalName, @Cause Exception cause);

    // @Message(id = 1014, value = "Invalid empty name given")
    // IllegalArgumentException invalidEmptyName();

    @Message(id = 1015, value = "Filesystem-backed realm encountered invalid file content in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidContent(Path path, int lineNumber, String name);

    @Message(id = 1016, value = "Filesystem-backed realm encountered missing required attribute \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmMissingAttribute(String attribute, Path path, int lineNumber, String name);

    @Message(id = 1017, value = "Filesystem-backed realm encountered invalid password format \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidPasswordFormat(String format, Path path, int lineNumber, String name);

    @Message(id = 1018, value = "Filesystem-backed realm encountered invalid password algorithm \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidPasswordAlgorithm(String algorithm, Path path, int lineNumber, String name);

//    @Message(id = 1019, value = "Unable to obtain exclusive access to backing identity")
//    RealmUnavailableException unableToObtainExclusiveAccess();

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

//    @Message(id = 1030, value = "Unable to read credential")
//    IOException unableToReadCredential(@Cause Exception e);

    // @Message(id = 1031, value = "Missing reference in extends")
    // IllegalArgumentException missingReferenceInExtends();

    // @Message(id = 1032, value = "Invalid combination of obtainable and verifiable")
    // IllegalArgumentException invalidCombinationOfObtainableAndVerifiable();

//    @Message(id = 1033, value = "User does not exist")
//    IllegalStateException userDoesNotExist();

//    @Message(id = 1034, value = "Invalid credential type specified")
//    IllegalStateException invalidCredentialTypeSpecified();

    @Message(id = 1035, value = "Unable to create key manager")
    IOException unableToCreateKeyManager(@Cause Exception e);

    @Message(id = 1036, value = "Unable to create trust manager")
    IOException unableToCreateTrustManager(@Cause Exception e);

//    @Message(id = 1037, value = "Certificate chain is empty")
//    IllegalArgumentException certificateChainIsEmpty();

    // @Message(id = 1038, value = "Could get not RSA key from query")
    // RuntimeException couldNotGetRsaKeyFromQuery(@Cause Throwable cause);

    // @Message(id = 1039, value = "Invalid algorithm \"%s\"")
    // RuntimeException invalidAlgorithm(String algorithm, @Cause Throwable cause);

    // @Message(id = 1040, value = "Could not parse private key")
    // RuntimeException couldNotParsePrivateKey(@Cause Throwable cause);

    @Message(id = 1041, value = "Could not obtain credential")
    RuntimeException couldNotObtainCredential();

    @Message(id = 1042, value = "Could not obtain credential")
    RuntimeException couldNotObtainCredentialWithCause(@Cause Throwable cause);

    @Message(id = 1043, value = "Invalid password key specification for algorithm \"%s\"")
    RuntimeException invalidPasswordKeySpecificationForAlgorithm(String algorithm, @Cause Throwable cause);

    // @Message(id = 1044, value = "Salt is expected when creating \"%s\" passwords")
    // RuntimeException saltIsExpectedWhenCreatingPasswords(String type);

    @Message(id = 1045, value = "Could not obtain PasswordFactory for algorithm \"%s\"")
    RuntimeException couldNotObtainPasswordFactoryForAlgorithm(String algorithm, @Cause Throwable cause);

    // @Message(id = 1046, value = "Unknown password type or algorithm \"%s\"")
    // InvalidKeyException unknownPasswordTypeOrAlgorithm(String algorithm);

    // @Message(id = 1047, value = "Password-based credentials must be either a char[] or ClearPassword")
    // RuntimeException passwordBasedCredentialsMustBeCharsOrClearPassword();

    // @Message(id = 1048, value = "Invalid password key for algorithm \"%s\"")
    // RuntimeException invalidPasswordKeyForAlgorithm(String algorithm, @Cause Throwable cause);

    @Message(id = 1049, value = "Could not open connection")
    RuntimeException couldNotOpenConnection(@Cause Throwable cause);

    @Message(id = 1050, value = "Could not execute query \"%s\"")
    RuntimeException couldNotExecuteQuery(String sql, @Cause Throwable cause);

    // @Message(id = 1051, value = "Could not resolve password algorithm for credential name \"%s\"")
    // InvalidKeyException couldNotResolveAlgorithmByCredentialName(String credentialName);

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

    @Message(id = 1057, value = "No DirContext supplier set")
    IllegalStateException noDirContextSupplierSet();

    @Message(id = 1058, value = "No principal mapping definition")
    IllegalStateException noPrincipalMappingDefinition();

//    @Message(id = 1059, value = "Public and private key algorithm names are mismatched")
//    IllegalArgumentException mismatchedPublicPrivateKeyAlgorithms();

    @Message(id = 1060, value = "Could not obtain principal")
    RuntimeException couldNotObtainPrincipal();

//    @Message(id = 1061, value = "Public key is null")
//    IllegalArgumentException publicKeyIsNull();

    @Message(id = 1062, value = "No provider URL has been set")
    IllegalStateException noProviderUrlSet();

//    @Message(id = 1063, value = "Private key is null")
//    IllegalArgumentException privateKeyIsNull();

    // Multi Use
    @Message(id = 1064, value = "Invalid identity name")
    IllegalArgumentException invalidName();

//    @Message(id = 1065, value = "Pattern requires a capture group")
//    IllegalArgumentException patternRequiresCaptureGroup();

//    @LogMessage(level = WARN)
//    @Message(id = 1066, value = "Invalid string count for mechanism database entry \"%s\"")
//    void warnInvalidStringCountForMechanismDatabaseEntry(String name);

//    @LogMessage(level = WARN)
//    @Message(id = 1067, value = "Invalid key exchange \"%s\" for mechanism database entry \"%s\"")
//    void warnInvalidKeyExchangeForMechanismDatabaseEntry(String value, String name);

//    @LogMessage(level = WARN)
//    @Message(id = 1068, value = "Invalid authentication \"%s\" for mechanism database entry \"%s\"")
//    void warnInvalidAuthenticationForMechanismDatabaseEntry(String value, String name);

//    @LogMessage(level = WARN)
//    @Message(id = 1069, value = "Invalid encryption \"%s\" for mechanism database entry \"%s\"")
//    void warnInvalidEncryptionForMechanismDatabaseEntry(String value, String name);

//    @LogMessage(level = WARN)
//    @Message(id = 1070, value = "Invalid digest \"%s\" for mechanism database entry \"%s\"")
//    void warnInvalidDigestForMechanismDatabaseEntry(String value, String name);

//    @LogMessage(level = WARN)
//    @Message(id = 1071, value = "Invalid protocol \"%s\" for mechanism database entry \"%s\"")
//    void warnInvalidProtocolForMechanismDatabaseEntry(String value, String name);

//    @LogMessage(level = WARN)
//    @Message(id = 1072, value = "Invalid level \"%s\" for mechanism database entry \"%s\"")
//    void warnInvalidLevelForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1073, value = "Invalid strength bits \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidStrengthBitsForMechanismDatabaseEntry(String value, String name);

//    @LogMessage(level = WARN)
//    @Message(id = 1074, value = "Invalid algorithm bits \"%s\" for mechanism database entry \"%s\"")
//    void warnInvalidAlgorithmBitsForMechanismDatabaseEntry(String value, String name);

//    @LogMessage(level = WARN)
//    @Message(id = 1075, value = "Invalid duplicate mechanism database entry \"%s\"")
//    void warnInvalidDuplicateMechanismDatabaseEntry(String name);

    @LogMessage(level = WARN)
    @Message(id = 1076, value = "Invalid duplicate OpenSSL-style alias \"%s\" for mechanism database entry \"%s\" (original is \"%s\")")
    void warnInvalidDuplicateOpenSslStyleAliasForMechanismDatabaseEntry(String alias, String name, String originalName);

//    @LogMessage(level = WARN)
//    @Message(id = 1077, value = "Invalid alias \"%s\" for missing mechanism database entry \"%s\"")
//    void warnInvalidAliasForMissingMechanismDatabaseEntry(String value, String name);

    // @Message(id = 1078, value = "Ldap-backed realm failed to obtain identity \"%s\" from server")
    // RealmUnavailableException ldapRealmFailedObtainIdentityFromServer(String identity, @Cause Throwable cause);

    @Message(id = 1079, value = "Ldap-backed realm failed to obtain attributes for entry [%s]")
    RuntimeException ldapRealmFailedObtainAttributes(String dn, @Cause Throwable cause);

    @Message(id = 1080, value = "Attribute [%s] value [%s] must be in X.500 format in order to obtain RDN [%s].")
    RuntimeException ldapRealmInvalidRdnForAttribute(String attributeName, String value, String rdn, @Cause Throwable cause);

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

//    @Message(id = 1088, value = "Attempting to run as \"%s\" authorization operation failed")
//    AuthorizationFailureException runAsAuthorizationFailed(@Param Principal principal, Principal targetPrincipal, @Cause Throwable cause);

    // @Message(id = 1089, value = "Attempting to run as \"%s\" authorization check failed (permission denied)")
    // AuthorizationCheckException unauthorizedRunAs(@Param Principal principal, Principal runAsPrincipal, @Param RunAsPrincipalPermission permission);

    @Message(id = 1090, value = "Unknown LDAP password scheme")
    InvalidKeySpecException unknownLdapPasswordScheme();

    @LogMessage(level = WARN)
    @Message(id = 1091, value = "Post-association peer context action failed")
    void postAssociationFailed(@Cause Throwable cause);

//    @Message(id = 1092, value = "Invalid mechanism realm selection \"%s\"")
//    IllegalArgumentException invalidMechRealmSelection(String realmName);

//    @Message(id = 1093, value = "Mechanism realm was already selected")
//    IllegalStateException mechRealmAlreadySelected();

//    @LogMessage(level = ERROR)
//    @Message(id = 1094, value = "An event handler threw an exception")
//    void eventHandlerFailed(@Cause Throwable cause);

//    @Message(id = 1095, value = "Unable to create identity")
//    RealmUnavailableException unableToCreateIdentity();

    // Multi Use
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
    RuntimeException tokenRealmFailedToObtainPrincipal(@Cause Throwable cause);

    @Message(id = 1105, value = "OAuth2-based realm failed to introspect token")
    RealmUnavailableException tokenRealmOAuth2TokenIntrospectionFailed(@Cause Throwable cause);

    @Message(id = 1106, value = "Could not obtain SSLContext")
    IllegalStateException failedToObtainSSLContext(@Cause Throwable cause);

    @Message(id = 1108, value = "Ldap-backed realm identity search failed")
    RealmUnavailableException ldapRealmIdentitySearchFailed(@Cause Throwable cause);

    @Message(id = 1109, value = "Ldap-backed realm is not configured to allow iterate over identities (iterator filter has to be set)")
    RealmUnavailableException ldapRealmNotConfiguredToSupportIteratingOverIdentities();

    // @Message(id = 1110, value = "Peer identities were already set on this context")
    // IllegalStateException peerIdentitiesAlreadySet();

    // @Message(id = 1111, value = "Ldap-backed realm paged iteration unsupported: PagedResultsResponseControl not provided by LdapContext in response control")
    // NamingException ldapRealmPagedControlNotProvidedByLdapContext();

//    @Message(id = 1112, value = "Authentication cannot succeed; not authorized")
//    IllegalStateException cannotSucceedNotAuthorized();

    @Message(id = 1113, value = "Token-based realm failed to obtain principal from token using claim [%s]")
    IllegalStateException tokenRealmFailedToObtainPrincipalWithClaim(String claimName);

    @Message(id = 1114, value = "Invalid token format. Tokens must have a signature part accordingly with JWS specification")
    IllegalArgumentException tokenRealmJwtInvalidFormat();

    @Message(id = 1115, value = "Failed to parse token")
    IllegalStateException tokenRealmJwtParseFailed(@Cause Throwable cause);

    @Message(id = 1116, value = "Signature verification failed")
    IllegalStateException tokenRealmJwtSignatureCheckFailed(@Cause Throwable cause);

    @Message(id = 1117, value = "Invalid signature algorithm [%s]")
    IllegalArgumentException tokenRealmJwtSignatureInvalidAlgorithm(String algorithm);

    @Message(id = 1118, value = "Public key could not be obtained. Probably due to an invalid PEM format.")
    IllegalArgumentException tokenRealmJwtInvalidPublicKeyPem();

//    @Message(id = 1119, value = "Unable to resolve MechanismConfiguration for mechanismType='%s', mechanismName='%s', hostName='%s', protocol='%s'.")
//    IllegalStateException unableToSelectMechanismConfiguration(String mechanismType, String mechanismName, String hostName, String protocol);

//    @Message(id = 1120, value = "Too late to set mechanism information as authentication has already begun.")
//    IllegalStateException tooLateToSetMechanismInformation();

//    @Message(id = 1121, value = "Unable to perform initial JAAS login.")
//    GeneralSecurityException unableToPerformInitialLogin(@Cause LoginException cause);

//    @Message(id = 1122, value = "No Kerberos principals found.")
//    GeneralSecurityException noKerberosPrincipalsFound();

//    @Message(id = 1123, value = "Too many Kerberos principals found.")
//    GeneralSecurityException tooManyKerberosPrincipalsFound();

//    @Message(id = 1124, value = "The security realm does not support updating a credential")
//    UnsupportedOperationException credentialUpdateNotSupportedByRealm();

    @Message(id = 1125, value = "Ldap-backed realm failed to obtain context")
    RealmUnavailableException ldapRealmFailedToObtainContext(@Cause Throwable cause);

    @LogMessage(level = WARN)
    @Message(id = 1126, value = "Jwt-based token realm not configured with a list of valid issuers. Ignoring issuer verification.")
    void tokenRealmJwtWarnNoIssuerIgnoringIssuerCheck();

    @LogMessage(level = WARN)
    @Message(id = 1127, value = "Jwt-based token not configured with a list of valid audiences. Ignoring audience verification.")
    void tokenRealmJwtWarnNoAudienceIgnoringAudienceCheck();

    @LogMessage(level = WARN)
    @Message(id = 1128, value = "Jwt-based token not configured with a public key. Ignoring signature verification.")
    void tokenRealmJwtWarnNoPublicKeyIgnoringSignatureCheck();

    @Message(id = 1129, value = "Unknown SSL context \"%s\" specified")
    ConfigXMLParseException xmlUnknownSslContextSpecified(@Param Location location, String name);

    @Message(id = 1130, value = "Duplicate SSL context name \"%s\"")
    ConfigXMLParseException xmlDuplicateSslContextName(String name, @Param ConfigurationXMLStreamReader reader);

    // 1131 "Public and private key parameters are mismatched" -> moved to credentials package

    @Message(id = 1132, value = "Unknown authentication configuration \"%s\" specified")
    ConfigXMLParseException xmlUnknownAuthenticationConfigurationSpecified(@Param Location location, String name);

    @Message(id = 1133, value = "Failed to create credential")
    ConfigXMLParseException xmlFailedToCreateCredential(@Param Location location, @Cause Throwable cause);

    @Message(id = 1134, value = "Duplicate authentication configuration name \"%s\"")
    ConfigXMLParseException xmlDuplicateAuthenticationConfigurationName(String name, @Param ConfigurationXMLStreamReader reader);

    @Message(id = 1135, value = "Failed to load keystore data")
    ConfigXMLParseException xmlFailedToLoadKeyStoreData(@Param Location location, @Cause Throwable cause);

    @Message(id = 1136, value = "Failed to create keystore")
    ConfigXMLParseException xmlFailedToCreateKeyStore(@Param Location location, @Cause Throwable cause);

    @Message(id = 1137, value = "Invalid key store entry type for alias \"%s\" (expected %s, got %s)")
    ConfigXMLParseException xmlInvalidKeyStoreEntryType(@Param Location location, String alias, Class<?> expectedClass, Class<?> actualClass);

    @Message(id = 1138, value = "Decoding hashed password from users property file failed - should not be set as plain-text property file?")
    RealmUnavailableException decodingHashedPasswordFromPropertiesRealmFailed(@Cause Exception e);

    @Message(id = 1139, value = "Failed to create credential store")
    ConfigXMLParseException xmlFailedToCreateCredentialStore(@Param Location location, @Cause Throwable cause);

    @Message(id = 1140, value = "Wrong PEM content type; expected %s, actually was %s")
    ConfigXMLParseException xmlWrongPemType(@Param ConfigurationXMLStreamReader reader, Class<?> expected, Class<?> actual);

    @Message(id = 1141, value = "No PEM content found")
    ConfigXMLParseException xmlNoPemContent(@Param ConfigurationXMLStreamReader reader);

    // @Message(id = 1142, value = "Invalid iteration count %d (must be at least 1)")
    // ConfigXMLParseException xmlInvalidIterationCount(@Param ConfigurationXMLStreamReader reader, int wrongCount);

    @Message(id = 1143, value = "Invalid URL [%s]")
    ConfigXMLParseException xmlInvalidUrl(String url);

    // @Message(id = 1144, value = "Realm failed to obtain identity from cache")
    // RuntimeException realmCacheFailedObtainIdentityFromCache(@Cause Throwable cause);

    // @Message(id = 1145, value = "Security realm [%s] must implement [%s]")
    // IllegalArgumentException realmCacheUnexpectedType(SecurityRealm realm, Class<? extends CacheableSecurityRealm> expectedType);

    @LogMessage
    @Message(id = 1146, value = "LDAP Realm unable to register listener, defering action.")
    void ldapRealmDeferRegistration();

    @Message(id = 1147, value = "Invalid LDAP name [%s]")
    RuntimeException ldapInvalidLdapName(String name, @Cause Throwable cause);

//    @Message(id = 1148, value = "A SecurityDomain has already been associated with the specified ClassLoader")
//    IllegalStateException classLoaderSecurityDomainExists();

//    @Message(id = 1149, value = "Can not use SecurityIdentity with SecurityIdentity from same SecurityDomain")
//    IllegalArgumentException cantWithSameSecurityDomainDomain();

    @Message(id = 1150, value = "Obtaining DirContext credentials from AuthenticationContext failed.")
    NamingException obtainingDirContextCredentialFromAuthenticationContextFailed(@Cause Throwable cause);

//    @Message(id = 1151, value = "Evidence Verification Failed.")
//    SecurityException authenticationFailedEvidenceVerification();

//    @Message(id = 1152, value = "Authorization Check Failed.")
//    SecurityException authenticationFailedAuthorization();

    @Message(id = 1153, value = "Direct LDAP verification failed with DN [%s] and absolute DN [%s]")
    RealmUnavailableException directLdapVerificationFailed(String distinguishedName, String absoluteName, @Cause Exception e);

    @Message(id = 1154, value = "Failed to read key store")
    RealmUnavailableException failedToReadKeyStore(@Cause KeyStoreException e);

//    @Message(id = 1155, value = "Security domain mismatch")
//    IllegalArgumentException securityDomainMismatch();

//    @Message(id = 1156, value = "Cannot obtain a credential from a security factory")
//    IOException cannotObtainCredentialFromFactory(@Cause GeneralSecurityException e);

    @LogMessage(level = WARN)
    @Message(id = 1157, value = "Unable to resolve MechanismConfiguration for MechanismInformation")
    void unableToResolveMechanismConfiguration(@Cause Throwable e);

    @Message(id = 1158, value = "Unable to create kerberos GSS credential")
    SecurityException unableToCreateKerberosCredential(@Cause Exception e);

    @Message(id = 1159, value = "Key store entry for alias \"%s\" is missing.")
    ConfigXMLParseException keyStoreEntryMissing(@Param Location location, String alias);

//    @Message(id = 1160, value = "KeyTab [%s] does not exists.")
//    IOException keyTabDoesNotExists(String keyTab);

//    @Message(id = 1161, value = "No keys for Kerberos principal [%s] was found in KeyTab [%s].")
//    IOException noKeysForPrincipalInKeyTab(String principal, String keyTab);

    @Message(id = 1162, value = "Invalid GSS mechanism name \"%s\" - unable to convert to mechanism OID")
    ConfigXMLParseException xmlInvalidGssMechanismName(@Param XMLStreamReader reader, String mechanismName);

    @Message(id = 1163, value = "Mechanism OID conversion from string \"%s\" failed")
    ConfigXMLParseException xmlGssMechanismOidConversionFailed(@Param XMLStreamReader reader, String mechanismOid, @Cause Throwable cause);

    @Message(id = 1164, value = "Unable to identify provider name=%s, for service type=%s, algorithm=%s")
    ConfigXMLParseException xmlUnableToIdentifyProvider(@Param Location location, String providerName, String serviceType, String algorithm);

//    @Message(id = 1165, value = "Initial JAAS login skipped as it has failed in last %d seconds")
//    GeneralSecurityException initialLoginSkipped(long seconds);

    @LogMessage(level = WARN)
    @Message(id = 1166, value = "%2$s: Element \"%1$s\" is deprecated")
    void xmlDeprecatedElement(String name, XMLLocation location);

//    @Message(id = 1167, value = "Unable to construct provider '%s'.")
//    SecurityException unableToConstructProvider(String className, @Cause Throwable cause);
//
//    @Message(id = 1168, value = "JASPIC Configuration for messageLayer=%s, and applicationContext=%s already registered.")
//    IllegalStateException configAlreadyRegistered(String messageLayer, String applicationContext);
//
//    @Message(id = 1169, value = "Message type '%s' is not supported by authentication module '%s'")
//    IllegalArgumentException unsupportedMessageType(String messageType, String authenticationModule);
//
//    @Message(id = 1170, value = "Unrecognised authContextId '%s'")
//    AuthException unrecognisedAuthContextId(String authContextId);
//
//    @Message(id = 1171, value = "Invalid message type '%s', expected '%s'.")
//    IllegalArgumentException invalidMessageType(String actualMessageType, String expectedMessageType);
//
//    @Message(id = 1172, value = "Message does not wrap existing message of type '%s'")
//    IllegalArgumentException messageDoesNotWrapExistingMessage(String messageType);
//
//    @Message(id = 1173, value = "Message does not un-wrap existing message of type '%s'")
//    IllegalArgumentException messageDoesNotUnWrapExistingMessage(String messageType);
//
//    @Message(id = 1174, value = "Setting message of type '%s' not allowed at this time.")
//    IllegalStateException messageSettingNotAllowed(String messageType);
//
//    @Message(id = 1175, value = "The wrapping or request / response messages is only allowed where AuthStatus==SUCCESS ServerAuthenticationModule=%s")
//    IllegalStateException messageWrappedWithoutSuccess(String module);
//
//    @Message(id = 1176, value = "Invalid AuthStatus %s returned from ServerAuthModule %s.")
//    IllegalStateException invalidAuthStatus(AuthStatus authStatus, String serverAuthModule);
//
//    @Message(id = 1177, value = "Authorization failed.")
//    IOException authorizationFailed();

    @LogMessage(level = WARN)
    @Message(id = 1178, value = "Unable to update jwk set from \"%1$s\".")
    void unableToFetchJwks(String url);

    @LogMessage(level = WARN)
    @Message(id = 1179, value = "SSL not configured. jku claim will not be supported.")
    void tokenRealmJwtNoSSLIgnoringJku();

    @LogMessage
    @Message(id = 1180, value = "Fetched jwk does not contain \"%1$s\" claim, ignoring...")
    void tokenRealmJwkMissingClaim(String claim);

    /* keystore package */

//    @Message(id = 2001, value = "Invalid key store entry password for alias \"%s\"")
//    UnrecoverableKeyException invalidKeyStoreEntryPassword(String alias);

//    @Message(id = 2002, value = "Invalid key store entry type for alias \"%s\" (expected %s, got %s)")
//    KeyStoreException invalidKeyStoreEntryType(String alias, Class<?> expectedClass, Class<?> actualClass);

//    @Message(id = 2003, value = "Key store key for alias \"%s\" cannot be protected")
//    KeyStoreException keyCannotBeProtected(String alias);

//    @Message(id = 2004, value = "Key store failed to translate password for alias \"%s\"")
//    IOException keyStoreFailedToTranslate(String alias, @Cause Throwable cause);

//    @Message(id = 2005, value = "Key store failed to identify a suitable algorithm for alias \"%s\"")
//    NoSuchAlgorithmException noAlgorithmForPassword(String alias);

//    @Message(id = 2006, value = "Unexpected whitespace in password file")
//    IOException unexpectedWhitespaceInPasswordFile();

//    @Message(id = 2007, value = "Unexpected end of file")
//    EOFException unexpectedEof();

//    @Message(id = 2008, value = "A reversible load is not possible until the KeyStore has first been initialized")
//    IllegalStateException reversibleLoadNotPossible();

    // Duplicated in wildfly-elytron-credential
//    @Message(id = 2009, value = "Unable to create a new KeyStore instance")
//    IOException unableToCreateKeyStore(@Cause Exception cause);

    @Message(id = 2010, value = "Unknown key store specified")
    ConfigXMLParseException xmlUnknownKeyStoreSpecified(@Param Location location);

    // id = 2011 "Failed to load keystore data"

    // id = 2012 KeyStoreException "Secret keys not supported"

    // id = 2013 KeyStoreException "Direct key storage not supported"

    // id = 2014 KeyStoreException "Only password storage is supported"

//    @Message(id = 2012, value = "An empty alias filter was supplied")
//    IllegalArgumentException emptyFilter();

//    @Message(id = 2013, value = "Filter is missing '+' or '-' at offset %d")
//    IllegalArgumentException missingPlusMinusAt(long position);

//    @Message(id = 2014, value = "Invalid first word '%s', must be one of ALL/NONE")
//    IllegalArgumentException invalidFirstWord(String firstWord);

//    @Message(id = 2015, value = "Failed to obtain DirContext")
//    IllegalStateException failedToObtainDirContext(@Cause Throwable cause);

//    @Message(id = 2016, value = "Failed to return DirContext")
//    IllegalStateException failedToReturnDirContext(@Cause Throwable cause);

    @Message(id = 2017, value = "LdapKeyStore failed to obtain alias [%s]")
    IllegalStateException ldapKeyStoreFailedToObtainAlias(String alias, @Cause Throwable cause);

//    @Message(id = 2018, value = "LdapKeyStore failed to obtain certificate [%s]")
//    IllegalStateException ldapKeyStoreFailedToObtainCertificate(String alias, @Cause Throwable cause);

//    @Message(id = 2019, value = "LdapKeyStore failed to obtain certificate chain [%s]")
//    IllegalStateException ldapKeyStoreFailedToObtainCertificateChain(String alias, @Cause Throwable cause);

//    @Message(id = 2020, value = "LdapKeyStore failed to recover key of alias [%s]")
//    IllegalStateException ldapKeyStoreFailedToObtainKey(String alias, @Cause Throwable cause);

//    @Message(id = 2021, value = "LdapKeyStore failed to obtain alias by certificate")
//    IllegalStateException ldapKeyStoreFailedToObtainAliasByCertificate(@Cause Throwable cause);

//    @Message(id = 2022, value = "LdapKeyStore failed to recover key of alias [%s]")
//    UnrecoverableKeyException ldapKeyStoreFailedToRecoverKey(String alias, @Cause Throwable cause);

//    @Message(id = 2023, value = "LdapKeyStore failed to obtain creation date of alias [%s]")
//    IllegalStateException ldapKeyStoreFailedToObtainCreationDate(String alias, @Cause Throwable cause);

//    @Message(id = 2024, value = "Alias [%s] does not exist in LdapKeyStore and not configured for creation")
//    KeyStoreException creationNotConfigured(String alias);

//    @Message(id = 2025, value = "LdapKeyStore failed store alias [%s]")
//    KeyStoreException ldapKeyStoreFailedToStore(String alias, @Cause Throwable cause);

//    @Message(id = 2026, value = "LdapKeyStore failed to serialize certificate of alias [%s]")
//    KeyStoreException ldapKeyStoreFailedToSerializeCertificate(String alias, @Cause Throwable cause);

//    @Message(id = 2027, value = "LdapKeyStore failed to protect (pack into keystore) key of alias [%s]")
//    KeyStoreException ldapKeyStoreFailedToSerializeKey(String alias, @Cause Throwable cause);

//    @Message(id = 2028, value = "LdapKeyStore failed to delete alias [%s]")
//    KeyStoreException ldapKeyStoreFailedToDelete(String alias, @Cause Throwable cause);

//    @Message(id = 2029, value = "LdapKeyStore failed to delete alias [%s] - alias not found")
//    KeyStoreException ldapKeyStoreFailedToDeleteNonExisting(String alias);

//    @Message(id = 2030, value = "LdapKeyStore failed to test alias [%s] existence")
//    IllegalStateException ldapKeyStoreFailedToTestAliasExistence(String alias, @Cause Throwable cause);

//    @Message(id = 2031, value = "LdapKeyStore failed to iterate aliases")
//    IllegalStateException ldapKeyStoreFailedToIterateAliases(@Cause Throwable cause);

//    @Message(id = 2032, value = "keySpec must be SecretKeySpect, given: [%s]")
//    InvalidKeySpecException keySpecMustBeSecretKeySpec(String type);

//    @Message(id = 2033, value = "key must implement SecretKeySpec and keySpec must be SecretKeySpec, given key, keySpec: [%s]")
//    InvalidKeySpecException keyMustImplementSecretKeySpecAndKeySpecMustBeSecretKeySpec(String keyAndKeySpec);

    @Message(id = 2034, value = "Alias must be specified if more than one entry exist in keystore")
    ConfigXMLParseException missingAlias(@Param Location location);

    /* util package */

//    @Message(id = 3001, value = "Unexpected padding")
//    DecodeException unexpectedPadding();

//    @Message(id = 3002, value = "Expected padding")
//    DecodeException expectedPadding();

//    @Message(id = 3003, value = "Incomplete decode")
//    DecodeException incompleteDecode();

//    @Message(id = 3004, value = "Expected %d padding characters")
//    DecodeException expectedPaddingCharacters(int numExpected);

//    @Message(id = 3005, value = "Invalid base 32 character")
//    DecodeException invalidBase32Character();

//    @Message(id = 3006, value = "Expected an even number of hex characters")
//    DecodeException expectedEvenNumberOfHexCharacters();

//    @Message(id = 3007, value = "Invalid hex character")
//    DecodeException invalidHexCharacter();

//    @Message(id = 3008, value = "Expected two padding characters")
//    DecodeException expectedTwoPaddingCharacters();

//    @Message(id = 3009, value = "Invalid base 64 character")
//    DecodeException invalidBase64Character();

//    @Message(id = 3010, value = "Malformed PEM content at offset %d")
//    IllegalArgumentException malformedPemContent(long offset);

//    @Message(id = 3011, value = "Invalid PEM type (expected \"%s\", got \"%s\"")
//    IllegalArgumentException invalidPemType(String expected, String actual);

//    @Message(id = 3012, value = "Certificate parse error")
//    IllegalArgumentException certificateParseError(@Cause CertificateException cause);

//    @Message(id = 3013, value = "Permission collection must be read-only")
//    SecurityException permissionCollectionMustBeReadOnly();

    // @Message(id = 3014, value = "Invalid character found in name \"%s\" at offset %d")
    // IllegalArgumentException invalidPermissionName(String name, int offset);

//    @Message(id = 3015, value = "Could not load permission class \"%s\"")
//    InvalidPermissionClassException permissionClassMissing(String className, @Cause ClassNotFoundException cause);

//    @Message(id = 3016, value = "Could not instantiate permission class \"%s\"")
//    InvalidPermissionClassException permissionInstantiation(String className, @Cause Throwable cause);

//    @Message(id = 3017, value = "No valid permission constructor found on class \"%s\"")
//    InvalidPermissionClassException noPermissionConstructor(String className);

    // Used by Permissions and JACC
    @Message(id = 3018, value = "Cannot add permissions to a read-only permission collection")
    SecurityException readOnlyPermissionCollection();

//    @Message(id = 3019, value = "Failure to deserialize object: field \"%s\" is null")
//    InvalidObjectException invalidObjectNull(String fieldName);

//    @Message(id = 3020, value = "Expected empty actions string, got \"%s\"")
//    IllegalArgumentException expectedEmptyActions(String actions);

//    @Message(id = 3021, value = "Invalid permission type; expected %s, got %s")
//    IllegalArgumentException invalidPermissionType(Class<? extends Permission> expected, Permission actual);

//    @Message(id = 3022, value = "Permission check failed: %s is not implied by %s")
//    SecurityException permissionCheckFailed(Permission permission, PermissionVerifier permissionVerifier);

//    @Message(id = 3023, value = "PublicKey parse error")
//    IllegalArgumentException publicKeyParseError(@Cause Throwable cause);

    // @Message(id = 3024, value = "Unsupported key encoding format [%s]")
    // IllegalArgumentException publicKeyUnsupportedEncodingFormat(String format);

    @Message(id = 3025, value = "Iteration count not specified for password based encryption")
    IllegalArgumentException iterationCountNotSpecified();

    @Message(id = 3026, value = "Salt not specified for password based encryption")
    IllegalArgumentException saltNotSpecified();

    @Message(id = 3027, value = "Initial key not specified for password based encryption")
    IllegalArgumentException initialKeyNotSpecified();

    @Message(id = 3028, value = "Security provider \"%s\" doesn't exist")
    IllegalArgumentException securityProviderDoesnExist(String providerName);

    @Message(id = 3029, value = "No such key algorithm \"%s\"")
    IllegalArgumentException noSuchKeyAlgorithm(String algorithmName, @Cause GeneralSecurityException cause);

//    @Message(id = 3030, value = "I/O operation failed: closed")
//    IOException closed();

//    @Message(id = 3031, value = "Too many KerberosTicket instances in private credentials")
//    GeneralSecurityException tooManyKerberosTicketsFound();

    @Message(id = 3032, value = "Base64 string created with unsupported PicketBox version \"%s\"")
    IllegalArgumentException wrongBase64InPBCompatibleMode(String base64);

//    @Message(id = 3033, value = "PrivateKey parse error")
//    IllegalArgumentException privateKeyParseError(@Cause Throwable cause);

    /* ssl package */

//    @Message(id = 4001, value = "No algorithm found matching TLS/SSL protocol selection criteria")
//    NoSuchAlgorithmException noAlgorithmForSslProtocol();

//    @Message(id = 4002, value = "Empty certificate chain is not trusted")
//    CertificateException emptyChainNotTrusted();

//    @Message(id = 4003, value = "Certificate not trusted due to realm failure for principal [%s]")
//    CertificateException notTrustedRealmProblem(@Cause RealmUnavailableException e, Principal principal);

//    @Message(id = 4004, value = "Credential validation failed: certificate is not trusted for principal [%s]")
//    CertificateException notTrusted(Principal principal);

    // Multi Use
    @Message(id = 4005, value = "No default trust manager available")
    NoSuchAlgorithmException noDefaultTrustManager();

//    @Message(id = 4006, value = "No context for SSL connection")
//    SSLHandshakeException noContextForSslConnection();

//    @Message(id = 4007, value = "SSL channel is closed")
//    SSLException sslClosed();

//    @Message(id = 4008, value = "Initial SSL/TLS data is not a handshake record")
//    SSLHandshakeException notHandshakeRecord();

//    @Message(id = 4009, value = "Initial SSL/TLS handshake record is invalid")
//    SSLHandshakeException invalidHandshakeRecord();

//    @Message(id = 4010, value = "Initial SSL/TLS handshake spans multiple records")
//    SSLHandshakeException multiRecordSSLHandshake();

//    @Message(id = 4011, value = "Expected \"client hello\" record")
//    SSLHandshakeException expectedClientHello();

//    @Message(id = 4012, value = "Unsupported SSL/TLS record")
//    SSLHandshakeException unsupportedSslRecord();

//    @Message(id = 4013, value = "Invalid TLS extension data")
//    SSLProtocolException invalidTlsExt();

//    @Message(id = 4014, value = "Not enough data in record to fill declared item size")
//    SSLProtocolException notEnoughData();

//    @Message(id = 4015, value = "Empty host name in SNI record data")
//    SSLProtocolException emptyHostNameSni();

//    @Message(id = 4016, value = "Duplicated SNI server name of type %d")
//    SSLProtocolException duplicatedSniServerName(int type);

//    @Message(id = 4017, value = "Unknown authentication name \"%s\"")
//    IllegalArgumentException unknownAuthenticationName(String name);

//    @Message(id = 4018, value = "Unknown encryption name \"%s\"")
//    IllegalArgumentException unknownEncryptionName(String name);

//    @Message(id = 4019, value = "Unknown key exchange name \"%s\"")
//    IllegalArgumentException unknownKeyExchangeName(String name);

    @Message(id = 4020, value = "Mechanism \"%s\" not supported by transformation mapper")
    IllegalArgumentException mechanismNotSupported(String mechanism);

    @Message(id = 4021, value = "Invalid index %d")
    IndexOutOfBoundsException invalidIndex(int index);

    @Message(id = 4022, value = "Invalid socket address type for URI")
    IllegalArgumentException invalidSocketAddressTypeForUri();

    @Message(id = 4023, value = "Too large")
    IllegalStateException tooLarge();

//    @Message(id = 4024, value = "Invalid client mode, expected %s, got %s")
//    IllegalArgumentException invalidClientMode(boolean expectedMode, boolean givenMode);

    @Message(id = 4025, value = "DirContext tries to connect without ThreadLocalSSLSocketFactory thread local setting")
    IllegalStateException threadLocalSslSocketFactoryThreadLocalNotSet();

//    @Message(id = 4026, value = "Could not create trust manager [%s]")
//    IllegalStateException sslErrorCreatingTrustManager(String name, @Cause Throwable cause);

//    @Message(id = 4027, value = "SecurityDomain of SSLContext does not support X509PeerCertificateChainEvidence verification")
//    IllegalArgumentException securityDomainOfSSLContextDoesNotSupportX509();

    @Message(id = 4028, value = "No default key manager available")
    NoSuchAlgorithmException noDefaultKeyManager();

//    @Message(id = 4029, value = "Default context cannot be null")
//    IllegalStateException defaultContextCannotBeNull();

//    @Message(id = 4030, value = "No context for SSL connection")
//    SSLException noSNIContextForSslConnection(); // TODO Compare with noContextForSslConnection.

    /* mechanism package */

    @Message(id = 5001, value = "Authentication mechanism exchange received a message after authentication was already complete")
    AuthenticationMechanismException mechMessageAfterComplete();

//    @Message(id = 5002, value = "Authentication mechanism user name contains an invalid or disallowed character")
//    AuthenticationMechanismException mechUserNameContainsInvalidCharacter();

    // 5003

//    @Message(id = 5004, value = "Authentication mechanism authorization failed")
//    AuthenticationMechanismException mechAuthorizationFailed(@Cause Throwable cause);

    @Message(id = 5005, value = "Authentication mechanism authentication is not yet complete")
    IllegalStateException mechAuthenticationNotComplete();

//    @Message(id = 5006, value = "Authentication mechanism does not support security layer (wrapping/unwrapping)")
//    IllegalStateException mechNoSecurityLayer();

//    @Message(id = 5007, value = "Invalid authentication mechanism negotiation message received")
//    AuthenticationMechanismException mechInvalidMessageReceived();

//    @Message(id = 5008, value = "No authentication mechanism login name was given")
//    AuthenticationMechanismException mechNoLoginNameGiven();

//    @Message(id = 5009, value = "No authentication mechanism password was given")
//    AuthenticationMechanismException mechNoPasswordGiven();

//    @Message(id = 5010, value = "Authentication mechanism authentication failed due to one or more malformed fields")
//    AuthenticationMechanismException mechMalformedFields(@Cause IllegalArgumentException ex);

//    @Message(id = 5011, value = "Authentication mechanism message is too long")
//    AuthenticationMechanismException mechMessageTooLong();

//    @Message(id = 5012, value = "Authentication mechanism server-side authentication failed")
//    AuthenticationMechanismException mechServerSideAuthenticationFailed(@Cause Exception e);

//    @Message(id = 5013, value = "Authentication mechanism password not verified")
//    AuthenticationMechanismException mechPasswordNotVerified();

//    @Message(id = 5014, value = "Authentication mechanism authorization failed: \"%s\" running as \"%s\"")
//    AuthenticationMechanismException mechAuthorizationFailed(String userName, String authorizationId);
    
    // Multi Use
    @Message(id = 5015, value = "Unexpected character U+%04x at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnexpectedChar(int codePoint, long offset, String string);

//    @Message(id = 5016, value = "Unrecognized token \"%s\" in mechanism selection string \"%s\"")
//    IllegalArgumentException mechSelectorUnknownToken(String word, String string);

    // Multi Use
    @Message(id = 5017, value = "Token \"%s\" not allowed at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorTokenNotAllowed(String token, long offset, String string);

//    @Message(id = 5018, value = "Channel binding data changed")
//    AuthenticationMechanismException mechChannelBindingChanged();

//    @Message(id = 5019, value = "No token was given")
//    AuthenticationMechanismException mechNoTokenGiven();

    @Message(id = 5020, value = "Unexpected end of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnexpectedEnd(String string);

    // 5021

//    @Message(id = 5022, value = "Initial challenge must be empty")
//    AuthenticationMechanismException mechInitialChallengeMustBeEmpty();
//
//    @Message(id = 5023, value = "Unable to set channel binding")
//    AuthenticationMechanismException mechUnableToSetChannelBinding(@Cause Exception e);
//
//    @Message(id = 5024, value = "Failed to determine channel binding status")
//    AuthenticationMechanismException mechFailedToDetermineChannelBindingStatus(@Cause Exception e);
//
//    @Message(id = 5025, value = "Mutual authentication not enabled")
//    AuthenticationMechanismException mechMutualAuthenticationNotEnabled();
//
//    @Message(id = 5026, value = "Unable to map SASL mechanism name to a GSS-API OID")
//    AuthenticationMechanismException mechMechanismToOidMappingFailed(@Cause Exception e);
//
//    @Message(id = 5027, value = "Unable to dispose of GSSContext")
//    AuthenticationMechanismException mechUnableToDisposeGssContext(@Cause Exception e);
//
//    @Message(id = 5028, value = "Unable to create name for acceptor")
//    AuthenticationMechanismException mechUnableToCreateNameForAcceptor(@Cause Exception e);

//    @Message(id = 5029, value = "Unable to create GSSContext")
//    AuthenticationMechanismException mechUnableToCreateGssContext(@Cause Exception e);

//    @Message(id = 5030, value = "Unable to set GSSContext request flags")
//    AuthenticationMechanismException mechUnableToSetGssContextRequestFlags(@Cause Exception e);
//
//    @Message(id = 5031, value = "Unable to accept SASL client message")
//    AuthenticationMechanismException mechUnableToAcceptClientMessage(@Cause Exception e);
//
//    @Message(id = 5032, value = "GSS-API mechanism mismatch between SASL client and server")
//    AuthenticationMechanismException mechGssApiMechanismMismatch();

//    @Message(id = 5033, value = "Channel binding not supported for this SASL mechanism")
//    AuthenticationMechanismException mechChannelBindingNotSupported();
//
//    @Message(id = 5034, value = "Channel binding type mismatch between SASL client and server")
//    AuthenticationMechanismException mechChannelBindingTypeMismatch();
//
//    @Message(id = 5035, value = "Channel binding not provided by client")
//    AuthenticationMechanismException mechChannelBindingNotProvided();

//    @Message(id = 5036, value = "Unable to determine peer name")
//    AuthenticationMechanismException mechUnableToDeterminePeerName(@Cause Exception e);
//
//    @Message(id = 5037, value = "Authentication mechanism client refuses to initiate authentication")
//    AuthenticationMechanismException mechClientRefusesToInitiateAuthentication();

//    @Message(id = 5038, value = "Nonces do not match")
//    AuthenticationMechanismException mechNoncesDoNotMatch();
//
//    @Message(id = 5039, value = "Invalid length of nonce received")
//    AuthenticationMechanismException invalidNonceLength();

//    @Message(id = 5040, value = "Iteration count %d is below the minimum of %d")
//    AuthenticationMechanismException mechIterationCountIsTooLow(int iterationCount, int minimumIterationCount);

//    @Message(id = 5041, value = "Iteration count %d is above the maximum of %d")
//    AuthenticationMechanismException mechIterationCountIsTooHigh(int iterationCount, int maximumIterationCount);

    // @Message(id = 5042, value = "[%s] Extensions unsupported")
    // AuthenticationMechanismException mechExtensionsUnsupported(String mechName);

//    @Message(id = 5043, value = "Invalid server message")
//    AuthenticationMechanismException mechInvalidServerMessage();
//
//    @Message(id = 5044, value = "Invalid server message")
//    AuthenticationMechanismException mechInvalidServerMessageWithCause(@Cause Throwable cause);

//    @Message(id = 5045, value = "Invalid client message")
//    AuthenticationMechanismException mechInvalidClientMessage();
//
//    @Message(id = 5046, value = "Invalid client message")
//    AuthenticationMechanismException mechInvalidClientMessageWithCause(@Cause Throwable cause);

//    @Message(id = 5047, value = "[%s] Authentication mechanism message is for mismatched mechanism \"%s\"")
//    AuthenticationMechanismException mechUnmatchedMechanism(String mechName, String otherMechName);

    // @Message(id = 5048, value = "[%s] Server rejected authentication")
    // AuthenticationMechanismException mechServerRejectedAuthentication(String mechName);

//    @Message(id = 5049, value = "Server authenticity cannot be verified")
//    AuthenticationMechanismException mechServerAuthenticityCannotBeVerified();

//    @Message(id = 5050, value = "Callback handler does not support user name")
//    AuthenticationMechanismException mechCallbackHandlerDoesNotSupportUserName(@Cause Throwable cause);

//    @Message(id = 5051, value = "Callback handler does not support credential acquisition")
//    AuthenticationMechanismException mechCallbackHandlerDoesNotSupportCredentialAcquisition(@Cause Throwable cause);
//
//    @Message(id = 5052, value = "Callback handler does not support authorization")
//    AuthenticationMechanismException mechAuthorizationUnsupported(@Cause Throwable cause);
//
    // Multi Use
    @Message(id = 5053, value = "Callback handler failed for unknown reason")
    AuthenticationMechanismException mechCallbackHandlerFailedForUnknownReason(@Cause Throwable cause);

    // @Message(id = 5054, value = "[%s] Salt must be specified")
    // AuthenticationMechanismException mechSaltMustBeSpecified(String mechName);

//    @Message(id = 5055, value = "Authentication rejected (invalid proof)")
//    AuthenticationMechanismException mechAuthenticationRejectedInvalidProof();

//    @Message(id = 5056, value = "Client sent extra message")
//    AuthenticationMechanismException mechClientSentExtraMessage();
//
//    @Message(id = 5057, value = "Server sent extra message")
//    AuthenticationMechanismException mechServerSentExtraMessage();

    @Message(id = 5058, value = "Authentication failed")
    AuthenticationMechanismException mechAuthenticationFailed();

    // @Message(id = 5059, value = "[%s] Invalid MAC initialization key")
    // AuthenticationMechanismException mechInvalidMacInitializationKey(String mechName);

//    @Message(id = 5060, value = "Empty number")
//    NumberFormatException emptyNumber();

//    @Message(id = 5061, value = "Invalid numeric character")
//    NumberFormatException invalidNumericCharacter();

//    @Message(id = 5062, value = "Too big number")
//    NumberFormatException tooBigNumber();

//    @Message(id = 5063, value = "Cannot get clear password from two way password")
//    AuthenticationMechanismException mechCannotGetTwoWayPasswordChars(@Cause Throwable cause);

//    @Message(id = 5064, value = "Hashing algorithm not supported")
//    AuthenticationMechanismException mechMacAlgorithmNotSupported(@Cause Throwable cause);

//    @Message(id = 5065, value = "keyword cannot be empty")
//    AuthenticationMechanismException mechKeywordCannotBeEmpty();

//    @Message(id = 5066, value = "No value found for keyword: %s")
//    AuthenticationMechanismException mechNoValueFoundForKeyword(String keyword);

//    @Message(id = 5067, value = "'=' expected after keyword: %s")
//    AuthenticationMechanismException mechKeywordNotFollowedByEqual(String keyword);

//    @Message(id = 5068, value = "Unmatched quote found for value: %s")
//    AuthenticationMechanismException mechUnmatchedQuoteFoundForValue(String value);

//    @Message(id = 5069, value = "Expecting comma or linear whitespace after quoted string: %s")
//    AuthenticationMechanismException mechExpectingCommaOrLinearWhitespaceAfterQuoted(String value);

//    @Message(id = 5070, value = "MessageType must equal to %d, but it is %d")
//    AuthenticationMechanismException mechMessageTypeMustEqual(int expected, int actual);
//
//    @Message(id = 5071, value = "Bad sequence number while unwrapping: expected %d, but %d received")
//    AuthenticationMechanismException mechBadSequenceNumberWhileUnwrapping(int expected, int actual);
//
//    @Message(id = 5072, value = "Problem during crypt")
//    AuthenticationMechanismException mechProblemDuringCrypt(@Cause Throwable cause);
//
//    @Message(id = 5073, value = "Problem during decrypt")
//    AuthenticationMechanismException mechProblemDuringDecrypt(@Cause Throwable cause);
//
//    @Message(id = 5074, value = "Unknown cipher \"%s\"")
//    AuthenticationMechanismException mechUnknownCipher(String cipher);

//    @Message(id = 5075, value = "Authorization ID changed unexpectedly")
//    AuthenticationMechanismException mechAuthorizationIdChanged();

//    @Message(id = 5076, value = "Problem getting required cipher. Check your transformation mapper settings.")
//    AuthenticationMechanismException mechProblemGettingRequiredCipher(@Cause Throwable cause);

//    @Message(id = 5077, value = "No common protection layer between client and server")
//    AuthenticationMechanismException mechNoCommonProtectionLayer();
//
//    @Message(id = 5078, value = "No common cipher between client and server")
//    AuthenticationMechanismException mechNoCommonCipher();
//
//    @Message(id = 5079, value = "No ciphers offered by server")
//    AuthenticationMechanismException mechNoCiphersOfferedByServer();

//    @Message(id = 5080, value = "Callback handler not provided user name")
//    AuthenticationMechanismException mechNotProvidedUserName();

    // @Message(id = 5081, value = "[%s] Callback handler not provided pre-digested password")
    // AuthenticationMechanismException mechNotProvidedPreDigested(String mechName);

    // @Message(id = 5082, value = "[%s] Callback handler not provided clear password")
    // AuthenticationMechanismException mechNotProvidedClearPassword(String mechName);

//    @Message(id = 5083, value = "Missing \"%s\" directive")
//    AuthenticationMechanismException mechMissingDirective(String directive);

//    @Message(id = 5084, value = "nonce-count must equal to %d, but it is %d")
//    AuthenticationMechanismException mechNonceCountMustEqual(int expected, int actual);
//
//    @Message(id = 5085, value = "Server is set to not support %s charset")
//    AuthenticationMechanismException mechUnsupportedCharset(String charset);
//
//    @Message(id = 5086, value = "Charset can be only \"utf-8\" or unspecified (to use ISO 8859-1)")
//    AuthenticationMechanismException mechUnknownCharset();

//    @Message(id = 5087, value = "Client selected realm not offered by server (%s)")
//    AuthenticationMechanismException mechDisallowedClientRealm(String clientRealm);

//    @Message(id = 5088, value = "digest-uri \"%s\" not accepted")
//    AuthenticationMechanismException mechMismatchedWrongDigestUri(String actual);
//
//    @Message(id = 5089, value = "Unexpected qop value: \"%s\"")
//    AuthenticationMechanismException mechUnexpectedQop(String qop);

    @Message(id = 5090, value = "Wrapping is not configured")
    IllegalStateException wrappingNotConfigured();

//    @Message(id = 5091, value = "Authentication name string is too long")
//    AuthenticationMechanismException mechAuthenticationNameTooLong();
//
//    @Message(id = 5092, value = "Authentication name is empty")
//    AuthenticationMechanismException mechAuthenticationNameIsEmpty();
//
//    @Message(id = 5093, value = "Authorization for anonymous access is denied")
//    AuthenticationMechanismException mechAnonymousAuthorizationDenied();
//
//    @Message(id = 5094, value = "Required padded length (%d) is less than length of conversion result (%d)")
//    IllegalArgumentException requiredNegativePadding(int totalLength, int hexLength);
//
//    @Message(id = 5095, value = "Invalid key provided for Digest HMAC computing")
//    AuthenticationMechanismException mechInvalidKeyForDigestHMAC();

    @Message(id = 5096, value = "Unable to read certificate from URL \"%s\"")
    IOException asnUnableToReadCertificateFromUrl(String url, @Cause Throwable cause);

//    @Message(id = 5097, value = "Unable to determine subject name from X.509 certificate")
//    IllegalStateException unableToDetermineSubjectName(@Cause Throwable cause);
//
//    @Message(id = 5098, value = "Unable to verify client signature")
//    AuthenticationMechanismException mechUnableToVerifyClientSignature(@Cause Throwable cause);
//
//    @Message(id = 5099, value = "Unable to verify server signature")
//    AuthenticationMechanismException mechUnableToVerifyServerSignature(@Cause Throwable cause);

    // @Message(id = 5100, value = "[%s] Unable to obtain other side certificate from URL \"%s\"")
    // AuthenticationMechanismException mechUnableToObtainServerCertificate(String mechName, String url, @Cause Throwable cause);

//    @Message(id = 5101, value = "Callback handler not provided server certificate")
//    AuthenticationMechanismException mechCallbackHandlerNotProvidedServerCertificate();
//
//    @Message(id = 5102, value = "Callback handler not provided client certificate")
//    AuthenticationMechanismException mechCallbackHandlerNotProvidedClientCertificate();
//
//    @Message(id = 5103, value = "Server identifier mismatch")
//    AuthenticationMechanismException mechServerIdentifierMismatch();
//
//    @Message(id = 5104, value = "Client identifier mismatch")
//    AuthenticationMechanismException mechClientIdentifierMismatch();
//
//    @Message(id = 5105, value = "Unable to determine client name")
//    AuthenticationMechanismException mechUnableToDetermineClientName(@Cause Throwable cause);
//
//    @Message(id = 5106, value = "Callback handler not provided private key")
//    AuthenticationMechanismException mechCallbackHandlerNotProvidedPrivateKey();
//
//    @Message(id = 5107, value = "Unable to create signature")
//    AuthenticationMechanismException mechUnableToCreateSignature(@Cause Throwable cause);
//
//    @Message(id = 5108, value = "Unable to create response token")
//    AuthenticationMechanismException mechUnableToCreateResponseToken(@Cause Throwable cause);
//
//    @Message(id = 5109, value = "Unable to create response token")
//    AuthenticationMechanismException mechUnableToCreateResponseTokenWithCause(@Cause Throwable cause);

//    @Message(id = 5110, value = "Invalid value for trusted authority type; expected a value between 0 and 4 (inclusive)")
//    IllegalArgumentException invalidValueForTrustedAuthorityType();

//    @Message(id = 5111, value = "Invalid value for a general name type; expected a value between 0 and 8 (inclusive)")
//    IllegalArgumentException invalidValueForGeneralNameType();

//    @Message(id = 5112, value = "Getting authentication mechanisms supported by GSS-API failed")
//    AuthenticationMechanismException mechGettingSupportedMechanismsFailed(@Cause Throwable cause);
//
//    @Message(id = 5113, value = "Unable to initialize OID of Kerberos V5")
//    RuntimeException unableToInitialiseOid(@Cause Throwable cause);
//
//    @Message(id = 5114, value = "Receive buffer requested '%d' is greater than supported maximum '%d'")
//    AuthenticationMechanismException mechReceiveBufferIsGreaterThanMaximum(int requested, int maximum);
//
//    @Message(id = 5115, value = "Unable to wrap message")
//    AuthenticationMechanismException mechUnableToWrapMessage(@Cause Throwable cause);
//
//    @Message(id = 5116, value = "Unable to unwrap message")
//    AuthenticationMechanismException mechUnableToUnwrapMessage(@Cause Throwable cause);
//
//    @Message(id = 5117, value = "Unable to unwrap security layer negotiation message")
//    AuthenticationMechanismException mechUnableToUnwrapSecurityLayerNegotiationMessage(@Cause Throwable cause);
//
//    @Message(id = 5118, value = "Invalid message of length %d on unwrapping")
//    AuthenticationMechanismException mechInvalidMessageOnUnwrapping(int length);
//
//    @Message(id = 5119, value = "Negotiated mechanism was not Kerberos V5")
//    AuthenticationMechanismException mechNegotiatedMechanismWasNotKerberosV5();
//
//    @Message(id = 5120, value = "Insufficient levels of protection available for supported security layers")
//    AuthenticationMechanismException mechInsufficientQopsAvailable();
//
//    @Message(id = 5121, value = "Unable to generate security layer challenge")
//    AuthenticationMechanismException mechUnableToGenerateChallenge(@Cause Throwable cause);
//
//    @Message(id = 5122, value = "Client selected a security layer that was not offered by server")
//    AuthenticationMechanismException mechSelectedUnofferedQop();
//
//    @Message(id = 5123, value = "No security layer selected but message length received")
//    AuthenticationMechanismException mechNoSecurityLayerButLengthReceived();
//
//    @Message(id = 5124, value = "Unable to get maximum size of message before wrap")
//    AuthenticationMechanismException mechUnableToGetMaximumSizeOfMessage(@Cause Throwable cause);

    // Multi Use
    @Message(id = 5125, value = "Unable to handle response from server")
    AuthenticationMechanismException mechUnableToHandleResponseFromServer(@Cause Throwable cause);

//    @Message(id = 5126, value = "Bad length of message for negotiating security layer")
//    AuthenticationMechanismException mechBadLengthOfMessageForNegotiatingSecurityLayer();
//
//    @Message(id = 5127, value = "No security layer supported by server but maximum message size received: \"%d\"")
//    AuthenticationMechanismException mechReceivedMaxMessageSizeWhenNoSecurityLayer(int length);
//
//    @Message(id = 5128, value = "Failed to read challenge file")
//    AuthenticationMechanismException mechFailedToReadChallengeFile(@Cause Throwable cause);
//
//    @Message(id = 5129, value = "Failed to create challenge file")
//    AuthenticationMechanismException mechFailedToCreateChallengeFile(@Cause Throwable cause);

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

    // @Message(id = 5149, value = "[%s] Authentication name changed unexpectedly")
    // AuthenticationMechanismException mechAuthenticationNameChanged(String mechName);

//    @Message(id = 5150, value = "Authentication mechanism authorization ID is too long")
//    AuthenticationMechanismException mechAuthorizationIdTooLong();

    // Also used in wildfly-elytron-credential
    @Message(id = 5151, value = "Invalid OTP algorithm \"%s\"")
    AuthenticationMechanismException mechInvalidOTPAlgorithm(String algorithm);

//    @Message(id = 5152, value = "Invalid OTP response type")
//    AuthenticationMechanismException mechInvalidOTPResponseType();
//
//    @Message(id = 5153, value = "Incorrect parity in SASL client message")
//    AuthenticationMechanismException mechIncorrectParity();
//
//    @Message(id = 5154, value = "Invalid character in seed")
//    AuthenticationMechanismException mechInvalidCharacterInSeed();
//
//    @Message(id = 5155, value = "Invalid OTP seed, must be between 1 and 16 characters long")
//    AuthenticationMechanismException mechInvalidOTPSeed();
//
//    @Message(id = 5156, value = "Invalid OTP pass phrase, must be between 10 and 63 characters long")
//    AuthenticationMechanismException mechInvalidOTPPassPhrase();
//
//    @Message(id = 5157, value = "Invalid OTP sequence number")
//    AuthenticationMechanismException mechInvalidOTPSequenceNumber();
//
//    @Message(id = 5158, value = "Invalid OTP")
//    AuthenticationMechanismException mechInvalidOTP();
//
//    @Message(id = 5159, value = "OTP pass phrase and seed must not match")
//    AuthenticationMechanismException mechOTPPassPhraseAndSeedMustNotMatch();
//
//    @Message(id = 5160, value = "Invalid OTP alternate dictionary")
//    AuthenticationMechanismException mechInvalidOTPAlternateDictionary();

//    @Message(id = 5161, value = "Unable to retrieve password for \"%s\"")
//    AuthenticationMechanismException mechUnableToRetrievePassword(String userName);

//    @Message(id = 5162, value = "Unable to update password for \"%s\"")
//    AuthenticationMechanismException mechUnableToUpdatePassword(String userName);

    @Message(id = 5163, value = "Authentication mechanism server timed out")
    AuthenticationMechanismException mechServerTimedOut();

//    @Message(id = 5164, value = "Unable to obtain exclusive access for \"%s\"")
//    AuthenticationMechanismException mechUnableToObtainExclusiveAccess(String userName);
//
//    @Message(id = 5165, value = "OTP re-initialization failed")
//    AuthenticationMechanismException mechOTPReinitializationFailed(@Cause Throwable cause);

//    @Message(id = 5166, value = "Server rejected authentication")
//    ScramServerException scramServerRejectedAuthentication(@Param ScramServerErrorCode errorCode);

//    @Message(id = 5167, value = "Invalid OTP password format type")
//    AuthenticationMechanismException mechInvalidOTPPasswordFormatType();

//    @Message(id = 5168, value = "Unsupported algorithm selected \"%s\"")
//    AuthenticationMechanismException mechUnsupportedAlgorithm(String algorithm);

//    @Message(id = 5169, value = "[%s] Clients response token does not match expected token")
//    String mechResponseTokenMismatch(String mechName);

//    @Message(id = 5170, value = "Problem during crypt: The encrypted result is null. The input data has a length of zero or too short to result in a new block.")
//    AuthenticationMechanismException mechProblemDuringCryptResultIsNull();
//
//    @Message(id = 5171, value = "Problem during decrypt: The decrypted result is null. The input data has a length of zero or too short to result in a new block.")
//    AuthenticationMechanismException mechProblemDuringDecryptResultIsNull();

    @Message(id = 5172, value = "Unable to locate MechanismConfiguration for mechanism.")
    AuthenticationMechanismException unableToLocateMechanismConfiguration(@Cause Throwable cause);

//    @Message(id = 5173, value = "Unable to obtain server credential.")
//    AuthenticationMechanismException unableToObtainServerCredential();

//    @Message(id = 5174, value = "Callback handler has not chosen realm")
//    AuthenticationMechanismException mechNotChosenRealm();

//    @Message(id = 5175, value = "Unable to determine bound server name")
//    AuthenticationMechanismException mechUnableToDetermineBoundServerName(@Cause Exception e);

//    @Message(id = 5176, value = "Unsupported callback")
//    AuthenticationMechanismException mechCallbackHandlerUnsupportedCallback(@Cause Throwable cause);

//    @Message(id = 5177, value = "One of \"%s\" and \"%s\" directives has to be defined")
//    AuthenticationMechanismException mechOneOfDirectivesHasToBeDefined(String directive1, String directive2);

    /* http package */

//    @Message(id = 6000, value = "Status code can not be set at this time.")
//    IllegalStateException statusCodeNotNow();

//    @Message(id = 6001, value = "An incorrectly formatted '%s'header was encountered.")
//    String incorrectlyFormattedHeader(String headerName);

//    @Message(id = 6002, value = "An authentication attempt for user '%s' failed validation using mechanism '%s'.")
//    String authenticationFailed(String username, String mechanismName);

//    @Message(id = 6003, value = "An authentication attempt failed validation.")
//    String authenticationFailed();

    // @Message(id = 6004, value = "Session management not supported. This is probably because no HttpSessionSpi was implemented for the underlying container.")
    // IllegalStateException httpSessionNotSupported();

//    @Message(id = 6005, value= "Attachments are not supported on this scope.")
//    UnsupportedOperationException noAttachmentSupport();

    @Message(id = 6006, value = "An authorization check for user '%s' failed.")
    String authorizationFailed(String username);

    @Message(id = 6007, value = "Username or password missing from authentication attempt.")
    String usernameOrPasswordMissing();

    @LogMessage(level = WARN)
    @Message(id = 6008, value = "Failed to logout participant [%s]. Participant will be removed from list of participants but its local session may still be active.")
    void warnHttpMechSsoFailedLogoutParticipant(String url, @Cause  Throwable cause);

    @Message(id = 6012, value = "Invalid logout message received for local session [%s]")
    IllegalStateException httpMechSsoInvalidLogoutMessage(String localSessionId);

    @LogMessage(level = ERROR)
    @Message(id = 6013, value = "Failed to invalidate local session")
    void errorHttpMechSsoFailedInvalidateLocalSession(@Cause  Throwable cause);

    @Message(id = 6014, value = "Authentication mechanism '%s' cannot be found")
    HttpAuthenticationException httpServerAuthenticationMechanismNotFound(String mechanismName);

//    @Message(id = 6015, value = "Unable to authenticate using DIGEST mechanism - realm name needs to be specified")
//    HttpAuthenticationException digestMechanismRequireRealm();

//    @Message(id = 6016, value = "HTTP authentication failed validating request, no mechanisms remain to continue authentication.")
//    HttpAuthenticationException httpAuthenticationFailedEvaluatingRequest();

//    @Message(id = 6017, value = "HTTP authentication is required but no authentication mechansims are available.")
//    HttpAuthenticationException httpAuthenticationNoMechanisms();

//    @Message(id = 6018, value = "HTTP authentication none of the responders successfuly sent a response.")
//    HttpAuthenticationException httpAuthenticationNoSuccessfulResponder();

//    @Message(id = 6019, value = "Unable to authenticate using DIGEST mechanism - mechanism realm name (%s) is not valid")
//    HttpAuthenticationException digestMechanismInvalidRealm(String realm);

//    @Message(id = 6020, value = "Scope unsuitable for use with authentication state '%s'")
//    IllegalArgumentException unsuitableScope(String scopeName);

//    @Message(id = 6021, value = "Unable to identify suitable HttpScope for mechanism state storage")
//    IllegalArgumentException unableToIdentifyHttpScope();

//    @Message(id = 6022, value = "Invalid nonce count %s")
//    HttpAuthenticationException invalidNonceCount(int nonceCount);

    /* asn1 package */

//    @Message(id = 7001, value = "Unrecognized encoding algorithm [%s]")
//    ASN1Exception asnUnrecognisedAlgorithm(String algorithm);

//    @Message(id = 7002, value = "Invalid general name type")
//    ASN1Exception asnInvalidGeneralNameType();

    // @Message(id = 7003, value = "Invalid trusted authority type")
    // ASN1Exception asnInvalidTrustedAuthorityType();

    // Duplicated in ASN.1
//    @Message(id = 7004, value = "Unexpected ASN.1 tag encountered")
//    ASN1Exception asnUnexpectedTag();
//
//    @Message(id = 7005, value = "Unable to read X.509 certificate data")
//    ASN1Exception asnUnableToReadCertificateData(@Cause Throwable cause);

//    @Message(id = 7006, value = "Invalid general name for URI type")
//    ASN1Exception asnInvalidGeneralNameForUriType(@Cause Throwable cause);

//    @Message(id = 7007, value = "Invalid general name for IP address type")
//    ASN1Exception asnInvalidGeneralNameForIpAddressType();

//    @Message(id = 7008, value = "IP address general name cannot be resolved")
//    ASN1Exception asnIpAddressGeneralNameCannotBeResolved(@Cause Throwable cause);

//    @Message(id = 7009, value = "No sequence to end")
//    IllegalStateException noSequenceToEnd();

//    @Message(id = 7010, value = "No set to end")
//    IllegalStateException noSetToEnd();

//    @Message(id = 7011, value = "No explicitly tagged element to end")
//    IllegalStateException noExplicitlyTaggedElementToEnd();

//    @Message(id = 7012, value = "Unexpected end of input")
//    ASN1Exception asnUnexpectedEndOfInput();
//
//    @Message(id = 7013, value = "Invalid number of unused bits")
//    ASN1Exception asnInvalidNumberOfUnusedBits();
//
//    @Message(id = 7014, value = "Non-zero length encountered for null type tag")
//    ASN1Exception asnNonZeroLengthForNullTypeTag();
//
//    @Message(id = 7015, value = "Invalid high-tag-number form")
//    ASN1Exception asnInvalidHighTagNumberForm();

//    @Message(id = 7016, value = "Length encoding exceeds 4 bytes")
//    ASN1Exception asnLengthEncodingExceeds4bytes();

//    @Message(id = 7017, value = "Invalid OID character")
//    ASN1Exception asnInvalidOidCharacter();

//    @Message(id = 7018, value = "OID must have at least 2 components")
//    ASN1Exception asnOidMustHaveAtLeast2Components();
//
//    @Message(id = 7019, value = "Invalid value for first OID component; expected 0, 1, or 2")
//    ASN1Exception asnInvalidValueForFirstOidComponent();

//    @Message(id = 7020, value = "Invalid value for second OID component; expected a value between 0 and 39 (inclusive)")
//    ASN1Exception asnInvalidValueForSecondOidComponent();

//    @Message(id = 7021, value = "Invalid length")
//    ASN1Exception asnInvalidLength();

//    @Message(id = 7022, value = "Unknown tag type: %d")
//    ASN1Exception asnUnknownTagType(int type);

//    @Message(id = 7023, value = "Unexpected character byte for printable string")
//    ASN1Exception asnUnexpectedCharacterByteForPrintableString();

//    @Message(id = 7024, value = "Invalid length encountered for boolean type tag")
//    ASN1Exception asnInvalidLengthForBooleanTypeTag();

      
//    @Message(id = 7025, value = "Invalid general name for URI type: missing scheme")
//    ASN1Exception asnInvalidGeneralNameForUriTypeMissingScheme();

    /* password package */

//    @Message(id = 8001, value = "Unrecognized key spec algorithm")
//    InvalidKeySpecException invalidKeySpecUnrecognizedKeySpecAlgorithm();

//    @Message(id = 8002, value = "Password spec cannot be rendered as a string")
//    InvalidKeySpecException invalidKeySpecPasswordSpecCannotBeRenderedAsString();

//    @Message(id = 8003, value = "Unknown crypt string algorithm")
//    InvalidKeySpecException invalidKeySpecUnknownCryptStringAlgorithm();

//    @Message(id = 8004, value = "Invalid character encountered")
//    InvalidKeySpecException invalidKeySpecInvalidCharacterEncountered();

//    @Message(id = 8005, value = "No iteration count terminator given")
//    InvalidKeySpecException invalidKeySpecNoIterationCountTerminatorGiven();

//    @Message(id = 8006, value = "Unexpected end of input string")
//    InvalidKeySpecException invalidKeySpecUnexpectedEndOfInputString();

//    @Message(id = 8007, value = "No salt terminator given")
//    InvalidKeySpecException invalidKeySpecNoSaltTerminatorGiven();

//    @Message(id = 8008, value = "Invalid hash length")
//    IllegalArgumentException invalidHashLength();

//    @Message(id = 8009, value = "Unexpected end of password string")
//    InvalidKeySpecException invalidKeySpecUnexpectedEndOfPasswordString();

//    @Message(id = 8010, value = "Unexpected end of password string")
//    InvalidKeySpecException invalidKeySpecUnexpectedEndOfPasswordStringWithCause(@Cause Throwable cause);

//    @Message(id = 8011, value = "Invalid minor version")
//    InvalidKeySpecException invalidKeySpecInvalidMinorVersion();

//    @Message(id = 8012, value = "Invalid cost: must be a two digit integer")
//    InvalidKeySpecException invalidKeySpecCostMustBeTwoDigitInteger();

//    @Message(id = 8013, value = "No such MessageDigest algorithm for \"%s\"")
//    InvalidKeySpecException invalidKeySpecNoSuchMessageDigestAlgorithm(String algorithm);

//    @Message(id = 8014, value = "No such MessageDigest algorithm for \"%s\"")
//    InvalidKeyException invalidKeyNoSuchMessageDigestAlgorithm(String algorithm);

//    @Message(id = 8015, value = "Cannot verify password")
//    InvalidKeyException invalidKeyCannotVerifyPassword(@Cause Throwable cause);

    // @Message(id = 8016, value = "DES crypt password hash must be %d bytes")
    // InvalidKeySpecException invalidKeySpecDesCryptPasswordHashMustBeBytes(int bytes);

//    @Message(id = 8017, value = "DES crypt password hash must be %d bytes")
//    InvalidKeyException invalidKeyDesCryptPasswordHashMustBeBytes(int bytes);

//    @Message(id = 8018, value = "Salt must be %d bytes (%d bits)")
//    InvalidParameterSpecException invalidParameterSpecSaltMustBeBytesBits(int bytes, int bits);

    // @Message(id = 8019, value = "Unsupported parameter spec")
    // InvalidParameterSpecException invalidParameterSpecUnsupportedParameterSpec();

//    @Message(id = 8020, value = "Invalid number of rounds. Must be an integer between %d and %d, inclusive")
//    IllegalArgumentException invalidNumberOfRoundsMustBeIntBetween(int min, int max);

//    @Message(id = 8021, value = "Invalid salt: must be %d bytes long")
//    IllegalArgumentException invalidSaltMustBeBytesLong(int length);

//    @Message(id = 8022, value = "BSD DES crypt password hash must be %d bytes")
//    InvalidKeySpecException invalidKeySpecBsdDesCryptPasswordHashMustBeBytes(int bytes);

//    @Message(id = 8023, value = "Salt must be %d bytes")
//    InvalidParameterSpecException invalidParameterSpecSaltMustBeBytes(int bytes);

//    @Message(id = 8024, value = "BSD DES crypt password hash must be %d bytes")
//    InvalidKeyException invalidKeyBsdDesCryptPasswordHashMustBeBytes(int bytes);

//    @Message(id = 8025, value = "Expected to get a \"%s\" as spec, got \"%s\"")
//    InvalidKeySpecException invalidKeySpecExpectedSpecGotSpec(String expected, String got);

//    @Message(id = 8026, value = "Unknown algorithm or incompatible PasswordSpec")
//    InvalidKeySpecException invalidKeySpecUnknownAlgorithmOrIncompatiblePasswordSpec();

//    @Message(id = 8027, value = "Unknown password type or algorithm")
//    InvalidKeyException invalidKeyUnknownUnknownPasswordTypeOrAlgorithm();

//    @Message(id = 8028, value = "Invalid algorithm \"%s\"")
//    NoSuchAlgorithmException noSuchAlgorithmInvalidAlgorithm(String algorithm);

//    @Message(id = 8029, value = "Could not obtain key spec encoding identifier.")
//    IllegalArgumentException couldNotObtainKeySpecEncodingIdentifier();

      
//    @Message(id = 8030, value = "Failed to encode parameter specification")
//    InvalidParameterSpecException failedToEncode(@Cause Throwable cause);

//    @Message(id = 8031, value = "Failed to decode parameter specification")
//    IOException failedToDecode(@Cause Throwable cause);

//    @Message(id = 8032, value = "Invalid parameter specification type (expected %s, got %s)")
//    InvalidParameterSpecException invalidParameterSpec(Class<?> expected, Class<?> actual);

//    @Message(id = 8033, value = "Invalid format given (expected %s, got %s)")
//    IOException invalidFormat(String expected, String actual);

//    @Message(id = 8034, value = "Algorithm parameters instance not initialized")
//    IllegalStateException algorithmParametersNotInitialized();

    /* authz package */

    //@LogMessage(level = ERROR)
    //@Message(id = 8500, value = "Failed to check permissions for protection domain [%s] and permission [%s].")
    //void authzFailedToCheckPermission(ProtectionDomain domain, Permission permission, @Cause Throwable cause);

    //@Message(id = 8501, value = "Invalid state [%s] for operation.")
    //UnsupportedOperationException authzInvalidStateForOperation(String actualState);

    //@Message(id = 8502, value = "Can't link policy configuration [%s] to itself.")
    //IllegalArgumentException authzLinkSamePolicyConfiguration(String contextID);

    //@Message(id = 8503, value = "ContextID not set. Check if the context id was set using PolicyContext.setContextID.")
    //IllegalStateException authzContextIdentifierNotSet();

    //@Message(id = 8504, value = "Invalid policy context identifier [%s].")
    //IllegalArgumentException authzInvalidPolicyContextIdentifier(String contextID);

    //@Message(id = 8505, value = "Could not obtain PolicyConfiguration for contextID [%s].")
    //PolicyContextException authzUnableToObtainPolicyConfiguration(String contextId, @Cause Throwable cause);

    //@Message(id = 8506, value = "Policy configuration with contextID [%s] is not in service state.")
    //IllegalStateException authzPolicyConfigurationNotInService(String contextID);

    // @LogMessage(level = ERROR)
    // @Message(id = 8507, value = "Could not obtain dynamic permissions.")
    // void authzFailedGetDynamicPermissions(@Cause Throwable cause);

    //@LogMessage(level = DEBUG)
    //@Message(id = 8508, value = "Could not obtain authorized identity.")
    //void authzCouldNotObtainSecurityIdentity(@Cause Throwable cause);

    // @Once
    // @LogMessage(level = WARN)
    // @Message(id = 8509, value = "Calling any of the Policy.getPermissions() methods is not supported; please see the "
    //     + "Java Authorization Contract for Containers (JACC) specification (section \"1.4 Requirements\", item 1) and "
    //     + "the Java SE API specification for the Policy.getPermissions() methods for more information.  Instead, use "
    //     + "the Policy.implies() method for authorization checking.")
    // void getPermissionsNotSupported();

//    @Message(id = 8510, value = "Role mapper has already been initialized.")
//    IllegalStateException roleMappedAlreadyInitialized();

//    @Message(id = 8511, value = "Role mapper hasn't been initialized yet.")
//    IllegalStateException roleMappedNotInitialized();

    /* credential package */

//    @Message(id = 9000, value = "Public and private key parameters are mismatched")
//    IllegalArgumentException mismatchedPublicPrivateKeyParameters();

    @Message(id = 9001, value = "Client credentials not provided")
    IllegalStateException oauth2ClientCredentialsNotProvided();

    /* credential.store. package */

//    @Message(id = 9500, value = "External storage key under alias \"%s\" has to be a SecretKey")
//    CredentialStoreException wrongTypeOfExternalStorageKey(String keyAlias);

    @Message(id = 9501, value = "Duplicate attribute (\"%s\") found in configuration.")
    ConfigXMLParseException duplicateAttributeFound(@Param XMLStreamReader reader, String attribute);

    @Message(id = 9502, value = "Duplicate credential store name found in configuration \"%s\"")
    ConfigXMLParseException duplicateCredentialStoreName(@Param XMLStreamReader reader, String storeName);

    @Message(id = 9503, value = "Credential store name \"%s\" not defined")
    ConfigXMLParseException xmlCredentialStoreNameNotDefined(@Param Location location, String storeName);

//    @Message(id = 9504, value = "Cannot acquire a credential from the credential store")
//    CredentialStoreException cannotAcquireCredentialFromStore(@Cause Throwable cause);

//    @Message(id = 9505, value = "Cannot perform operation '%s': Credential store is set non modifiable")
//    CredentialStoreException nonModifiableCredentialStore(String operation);

//    @Message(id = 9506, value = "Credential store command interrupted")
//    InterruptedIOException credentialCommandInterrupted();

//    @Message(id = 9507, value = "Invalid protection parameter given: %s")
//    CredentialStoreException invalidProtectionParameter(CredentialStore.ProtectionParameter protectionParameter);

//    @Message(id = 9508, value = "Cannot write credential to store")
//    CredentialStoreException cannotWriteCredentialToStore(@Cause Throwable cause);

//    @Message(id = 9509, value = "Unsupported credential type %s")
//    UnsupportedCredentialTypeException unsupportedCredentialType(Class<?> type);

//    @Message(id = 9510, value = "Invalid credential store keystore entry %s: expected %s")
//    CredentialStoreException invalidCredentialStoreEntryType(Class<? extends KeyStore.Entry> entryType, Class<? extends KeyStore.Entry> expectedType);

      // Used in Credential Store and Source
//    @Message(id = 9511, value = "Unable to read credential %s from store")
//    CredentialStoreException unableToReadCredentialTypeFromStore(Class<? extends Credential> credentialType);

//    @Message(id = 9512, value = "Unable to remove credential from store")
//    CredentialStoreException cannotRemoveCredentialFromStore(@Cause Throwable cause);

//    @Message(id = 9513, value = "Unable to flush credential store to storage")
//    CredentialStoreException cannotFlushCredentialStore(@Cause Throwable cause);

//    @Message(id = 9514, value = "Unable to initialize credential store")
//    CredentialStoreException cannotInitializeCredentialStore(@Cause Throwable cause);

//    @Message(id = 9515, value = "Ignored unrecognized key store entry \"%s\"")
//    @LogMessage(level = DEBUG)
//    void logIgnoredUnrecognizedKeyStoreEntry(String alias);

//    @Message(id = 9516, value = "Failed to read a credential entry from the key store")
//    @LogMessage(level = WARN)
//    void logFailedToReadKeyFromKeyStore(@Cause Throwable cause);

//    @Message(id = 9517, value = "This credential store type requires a store-wide protection parameter")
//    CredentialStoreException protectionParameterRequired();

//    @Message(id = 9518, value = "Automatic storage creation for the Credential Store is disabled \"%s\"")
//    CredentialStoreException automaticStorageCreationDisabled(String location);

//    @Message(id = 9519, value = "Unexpected credential store external storage file version \"%s\"")
//    IOException unexpectedFileVersion(String version);

//    @Message(id = 9520, value = "Unrecognized entry type \"%s\"")
//    IOException unrecognizedEntryType(String entryType);

//    @Message(id = 9521, value = "Internal encryption problem while reading \"%s\"")
//    IOException internalEncryptionProblem(@Cause Exception e, String location);

//    @Message(id = 9522, value = "\"%s\" is not a block based algorithm")
//    CredentialStoreException algorithmNotBlockBased(String algorithm);

//    @Message(id = 9523, value = "Algorithm \"%s\" does not use an initialization vector (IV)")
//    CredentialStoreException algorithmNotIV(String algorithm);

//    @Message(id = 9524, value = "The actual number of bytes read %d is different from the expected number of bytes %d to be read")
//    IOException readBytesMismatch(int actual, int expected);

//    @Message(id = 9525, value = "location and externalPath initial attributes are the same. [location=%s, externalPath=%s]")
//    CredentialStoreException locationAndExternalPathAreIdentical(String location, String externalPath);

//    @Message(id = 9526, value = "Unable to initialize credential store as attribute %s is unsupported in %s" )
//    CredentialStoreException unsupportedAttribute(String attribute, List<String> validAttribute);

    @Message(id = 9527, value = "Invalid credential store reference")
    ConfigXMLParseException xmlInvalidCredentialStoreRef(@Param Location location);

//    @Message(id = 9528, value = "The externalPath attribute for key store type %s is missing.")
//    CredentialStoreException externalPathMissing(String keyStoreType);


    /* X.500 exceptions */

//    @Message(id = 10000, value = "X.509 certificate extension with OID %s already exists")
//    IllegalArgumentException extensionAlreadyExists(String oid);

//    @Message(id = 10001, value = "No signature algorithm name given")
//    IllegalArgumentException noSignatureAlgorithmNameGiven();

//    @Message(id = 10002, value = "Signature algorithm name \"%s\" is not recognized")
//    IllegalArgumentException unknownSignatureAlgorithmName(String signatureAlgorithmName);

//    @Message(id = 10003, value = "No signing key given")
//    IllegalArgumentException noSigningKeyGiven();

//    @Message(id = 10004, value = "Signing key algorithm name \"%s\" is not compatible with signature algorithm name \"%s\"")
//    IllegalArgumentException signingKeyNotCompatWithSig(String signingKeyAlgorithm, String signatureAlgorithmName);

//    @Message(id = 10005, value = "Not-valid-before date of %s is after not-valid-after date of %s")
//    IllegalArgumentException validAfterBeforeValidBefore(ZonedDateTime notValidBefore, ZonedDateTime notValidAfter);

//    @Message(id = 10006, value = "No issuer DN given")
//    IllegalArgumentException noIssuerDnGiven();
//
//    @Message(id = 10007, value = "No public key given")
//    IllegalArgumentException noPublicKeyGiven();

//    @Message(id = 10008, value = "Issuer and subject unique ID are only allowed in certificates with version 2 or higher")
//    IllegalArgumentException uniqueIdNotAllowed();
//
//    @Message(id = 10009, value = "Extensions are only allowed in certificates with version 3 or higher")
//    IllegalArgumentException extensionsNotAllowed();

//    @Message(id = 10010, value = "X.509 encoding of public key with algorithm \"%s\" failed")
//    IllegalArgumentException invalidKeyForCert(String publicKeyAlgorithm, @Cause Exception cause);

//    @Message(id = 10011, value = "Failed to sign certificate")
//    IllegalArgumentException certSigningFailed(@Cause Exception cause);

//    @Message(id = 10012, value = "Certificate serial number must be positive")
//    IllegalArgumentException serialNumberTooSmall();
//
//    @Message(id = 10013, value = "Certificate serial number too large (cannot exceed 20 octets)")
//    IllegalArgumentException serialNumberTooLarge();

//    @Message(id = 10014, value = "Failed to sign certification request info")
//    IllegalArgumentException certRequestInfoSigningFailed(@Cause Exception cause);

//    @Message(id = 10015, value = "No certificate given")
//    IllegalArgumentException noCertificateGiven();

//    @Message(id = 10016, value = "Unable to determine key size")
//    IllegalArgumentException unableToDetermineKeySize();

//    @Message(id = 10017, value = "No DN given")
//    IllegalArgumentException noDnGiven();

//    @Message(id = 10018, value = "Failed to generate self-signed X.509 certificate")
//    IllegalArgumentException selfSignedCertificateGenerationFailed(@Cause Exception cause);

//    @Message(id = 10019, value = "Unable to determine default compatible signature algorithm name for key algorithm name \"%s\"")
//    IllegalArgumentException unableToDetermineDefaultCompatibleSignatureAlgorithmName(String keyAlgorithmName);

//    @Message(id = 10020, value = "Creating an X.509 certificate extension from a string value is not supported for extension name \"%s\"")
//    IllegalArgumentException certificateExtensionCreationFromStringNotSupported(String extensionName);

//    @Message(id = 10021, value = "Invalid X.509 certificate extension string value \"%s\"")
//    IllegalArgumentException invalidCertificateExtensionStringValue(String extensionValue);

//    @Message(id = 10022, value = "Failed to create X.509 certificate extension from string value")
//    IllegalArgumentException certificateExtensionCreationFromStringFailed(@Cause Exception cause);

//    @Message(id = 10023, value = "X.509 certificate extension \"%s\" must be non-critical")
//    IllegalArgumentException certificateExtensionMustBeNonCritical(String extensionName);

//    @Message(id = 10024, value = "Invalid X.509 certificate extension string value")
//    IllegalArgumentException invalidCertificateExtensionStringValue();

//    @Message(id = 10025, value = "Non-X.509 certificate found in certificate array")
//    IllegalArgumentException nonX509CertificateInCertificateArray();

//    @Message(id = 10026, value = "Starting public key not found in certificate array")
//    IllegalArgumentException startingPublicKeyNotFoundInCertificateArray();

//    @Message(id = 10027, value = "Incomplete certificate array")
//    IllegalArgumentException incompleteCertificateArray();

//    @Message(id = 10028, value = "Unable to create X.509 certificate chain from map of certificates")
//    IllegalArgumentException unableToCreateCertificateChainFromCertificateMap();

//    @Message(id = 10029, value = "Failed to generate ACME account key pair")
//    IllegalArgumentException acmeAccountKeyPairGenerationFailed(@Cause Exception cause);
//
//    @Message(id = 10030, value = "No ACME server URL given")
//    IllegalArgumentException noAcmeServerUrlGiven();
//
//    @Message(id = 10031, value = "Unsupported ACME account signature algorithm \"%s\"")
//    IllegalArgumentException unsupportedAcmeAccountSignatureAlgorithm(String signatureAlgorithm);
//
//    @Message(id = 10032, value = "Unable to create ACME signature")
//    IllegalArgumentException unableToCreateAcmeSignature(@Cause Exception cause);
//
//    @Message(id = 10033, value = "Unable to retrieve ACME server directory URLs")
//    AcmeException unableToRetrieveAcmeServerDirectoryUrls(@Cause Exception cause);
//
//    @Message(id = 10034, value = "No nonce provided by ACME server")
//    AcmeException noNonceProvidedByAcmeServer();
//
//    @Message(id = 10035, value = "No account location URL provided by ACME server")
//    AcmeException noAccountLocationUrlProvidedByAcmeServer();
//
//    @Message(id = 10036, value = "Unable to obtain new nonce from ACME server")
//    AcmeException unableToObtainNewNonceFromAcmeServer();
//
//    @Message(id = 10037, value = "Unable to obtain JSON response from ACME server")
//    AcmeException unableToObtainJsonResponseFromAcmeServer(@Cause Exception cause);
//
//    @Message(id = 10038, value = "Unexpected HTTP status code in response from ACME server \"%d\": \"%s\"")
//    AcmeException unexpectedResponseCodeFromAcmeServer(int responseCode, String responseMessage);
//
//    @Message(id = 10039, value = "Bad ACME replay nonce, maximum retries attempted")
//    AcmeException badAcmeNonce();
//
//    @Message(id = 10040, value = "Unexpected content type in response from ACME server \"%s\"")
//    AcmeException unexpectedContentTypeFromAcmeServer(String contentType);
//
//    @Message(id = 10041, value = "Invalid content type in response from ACME server")
//    AcmeException invalidContentTypeFromAcmeServer();
//
//    @Message(id = 10042, value = "Domain name is null")
//    AcmeException domainNameIsNull();
//
//    @Message(id = 10043, value = "Domain names is empty")
//    AcmeException domainNamesIsEmpty();
//
//    @Message(id = 10044, value = "No certificate URL provided by ACME server")
//    AcmeException noCertificateUrlProvidedByAcmeServer();
//
//    @Message(id = 10045, value = "No certificate will be issued by the ACME server")
//    AcmeException noCertificateWillBeIssuedByAcmeServer();
//
//    @Message(id = 10046, value = "Unable to get encoded form of certificate to be revoked")
//    AcmeException unableToGetEncodedFormOfCertificateToBeRevoked(@Cause Exception cause);
//
//    @Message(id = 10047, value = "Unable to determine key authorization string")
//    AcmeException unableToDetermineKeyAuthorizationString(@Cause Exception cause);
//
//    @Message(id = 10048, value = "Challenge response failed validation by the ACME server")
//    AcmeException challengeResponseFailedValidationByAcmeServer();
//
//    @Message(id = 10049, value = "Unable to download certificate chain from ACME server")
//    AcmeException unableToDownloadCertificateChainFromAcmeServer(@Cause Exception cause);
//
//    @Message(id = 10050, value = "ACME account does not exist")
//    AcmeException acmeAccountDoesNotExist();
//
//    @Message(id = 10051, value = "User action required since the ACME server's terms of service have changed, visit \"%s\" for details")
//    AcmeException userActionRequired(String url);
//
//    @Message(id = 10052, value = "Rate limit has been exceeded, try again after \"%s\"")
//    AcmeException rateLimitExceededTryAgainLater(Instant instant);
//
//    @Message(id = 10053, value = "Rate limit has been exceeded")
//    AcmeException rateLimitExceeded();
//
//    @Message(id = 10054, value = "Resource not supported by the ACME server \"%s\"")
//    AcmeException resourceNotSupportedByAcmeServer(String resource);
//
//    @Message(id = 10055, value = "Unsupported ACME account public key type \"%s\"")
//    IllegalArgumentException unsupportedAcmeAccountPublicKeyType(String keyAlgorithmName);
//
//    @Message(id = 10056, value = "Unable to determine curve parameter from alg header \"%s\"")
//    IllegalArgumentException unableToDetermineCurveParameterFromAlgHeader(String algHeader);

    /* Audit Exceptions */

    // 11000 - Unused in any Final release

    //@LogMessage(level = Logger.Level.FATAL)
    //@Message(id = 11001, value = "Endpoint unable to handle SecurityEvent priority=%s, message=%s")
    //void endpointUnavaiable(String priority, String message, @Cause Throwable cause);

    //@Message(id = 11002, value = "Invalid EventPriority '%s' passed to AuditEndpoint.")
    //IllegalArgumentException invalidEventPriority(EventPriority eventPriority);

    //@LogMessage(level = Logger.Level.ERROR)
    //@Message(id = 11003, value = "Unable to rotate log file")
    //void unableToRotateLogFile( @Cause Throwable cause);

    //@Message(id = 11004, value = "Invalid suffix \"%s\" - rotating by second or millisecond is not supported")
    //IllegalArgumentException rotatingBySecondUnsupported(String suffix);

    @Message(id = 11005, value = "Invalid unicode endoding, offending sequence: %s.")
    IOException invalidUnicodeSequence(String s, @Cause NoSuchElementException nsee);

//    @Message(id = 11006, value = "External storage key under alias \"%s\" does not exist")
//    CredentialStoreException externalStorageKeyDoesNotExist(String keyAlias);

    //@LogMessage(level = Logger.Level.FATAL)
    //@Message(id = 11007, value = "Endpoint unable to accept SecurityEvent.")
    //void unableToAcceptEvent(@Cause Throwable cause);
}
