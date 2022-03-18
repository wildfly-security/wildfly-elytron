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
package org.wildfly.security.auth.realm;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.Principal;
import java.util.NoSuchElementException;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.Param;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 1006, max = 1082),
    @ValidIdRange(min = 1138, max = 1154),
    @ValidIdRange(min = 11005, max = 11005),
    @ValidIdRange(min = 13000, max = 13999)
})
interface ElytronMessages extends BasicLogger {
    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 1006, value = "No realm name found in users property file - non-plain-text users file must contain \"#$REALM_NAME=RealmName$\" line")
    RealmUnavailableException noRealmFoundInProperties();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 1007, value = "JAAS authentication failed for principal %s")
    void debugInfoJaasAuthenticationFailure(Principal principal, @Cause Throwable cause);

    @Message(id = 1008, value = "Failed to create login context")
    RealmUnavailableException failedToCreateLoginContext(@Cause Throwable cause);

    @Message(id = 1009, value = "Failed to instantiate custom CallbackHandler")
    RealmUnavailableException failedToInstantiateCustomHandler(@Cause Throwable cause);

    @Message(id = 1012, value = "Filesystem-backed realm unexpectedly failed to open path \"%s\" for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmFailedToOpen(Path path, String finalName, @Cause IOException cause);

    @Message(id = 1013, value = "Filesystem-backed realm unexpectedly failed to read path \"%s\" for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmFailedToRead(Path path, String finalName, @Cause Exception cause);

    @Message(id = 1015, value = "Filesystem-backed realm encountered invalid file content in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidContent(Path path, int lineNumber, String name);

    @Message(id = 1016, value = "Filesystem-backed realm encountered missing required attribute \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmMissingAttribute(String attribute, Path path, int lineNumber, String name);

    @Message(id = 1017, value = "Filesystem-backed realm encountered invalid password format \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidPasswordFormat(String format, Path path, int lineNumber, String name);

    @Message(id = 1018, value = "Filesystem-backed realm encountered invalid password algorithm \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidPasswordAlgorithm(String algorithm, Path path, int lineNumber, String name);

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

    @Message(id = 1064, value = "Invalid identity name")
    IllegalArgumentException invalidName();

    @Message(id = 1081, value = "Filesystem-backed realm encountered invalid OTP definition in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidOtpDefinition(Path path, int lineNumber, String name, @Cause Throwable cause);

    @Message(id = 1082, value = "Filesystem-backed realm encountered invalid OTP algorithm \"%s\" in path \"%s\" line %d for identity name \"%s\"")
    RealmUnavailableException fileSystemRealmInvalidOtpAlgorithm(String algorithm, Path path, int lineNumber, String name, @Cause Throwable cause);

    @Message(id = 1138, value = "Decoding hashed password from users property file failed - should not be set as plain-text property file?")
    RealmUnavailableException decodingHashedPasswordFromPropertiesRealmFailed(@Cause Exception e);

    @Message(id = 1145, value = "Security realm [%s] must implement [%s]")
    IllegalArgumentException realmCacheUnexpectedType(SecurityRealm realm, Class<? extends CacheableSecurityRealm> expectedType);

    @Message(id = 13000, value = "Authorization principal cannot be null after transformation")
    IllegalStateException transformedPrincipalCannotBeNull();

    @Message(id = 1154, value = "Failed to read key store")
    RealmUnavailableException failedToReadKeyStore(@Cause KeyStoreException e);

    @Message(id = 11005, value = "Invalid unicode endoding, offending sequence: %s.")
    IOException invalidUnicodeSequence(String s, @Cause NoSuchElementException nsee);

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 13001, value = "Realm is failing over.")
    void realmFailover(@Cause RealmUnavailableException rue);

    @Message(id = 13002, value = "%s does not handle a callback of type %s")
    UnsupportedCallbackException unableToHandleCallback(@Param Callback callback, String callbackHandler, String callbackType);

    @Message(id = 13003, value = "Failed to load JAAS configuration file.")
    RealmUnavailableException failedToLoadJaasConfigFile();

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 13004, value = "JAAS logout failed for principal %s")
    void debugInfoJaasLogoutFailure(Principal principal, @Cause Throwable cause);

    @Message(id = 13005, value = "Filesystem-backed realm unable to decrypt identity")
    RealmUnavailableException fileSystemRealmDecryptionFailed(@Cause Throwable cause);

    @Message(id = 13006, value = "Filesystem-backed realm unable to encrypt identity")
    RealmUnavailableException fileSystemRealmEncryptionFailed(@Cause Throwable cause);

    @Message(id = 13007, value = "Filesystem-backed realm found an incompatible identity version. Requires at least version: %s")
    RealmUnavailableException fileSystemRealmIncompatibleIdentityVersion(String expectedVersion);
}
