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

package org.wildfly.security.credential.store._private;

import static org.jboss.logging.Logger.Level.DEBUG;
import static org.jboss.logging.Logger.Level.WARN;

import java.io.IOException;
import java.security.KeyStore;
import java.util.List;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 2009, max = 2009),
    @ValidIdRange(min = 9500, max = 9528),
    @ValidIdRange(min = 11006, max = 11006),
    @ValidIdRange(min = 12000, max = 12999)
})
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    // Duplicated in wildfly-elytron-credential
    @Message(id = 2009, value = "Unable to create a new KeyStore instance")
    IOException unableToCreateKeyStore(@Cause Exception cause);

    @Message(id = 9500, value = "External storage key under alias \"%s\" has to be a SecretKey")
    CredentialStoreException wrongTypeOfExternalStorageKey(String keyAlias);

    @Message(id = 9504, value = "Cannot acquire a credential from the credential store")
    CredentialStoreException cannotAcquireCredentialFromStore(@Cause Throwable cause);

    @Message(id = 9505, value = "Cannot perform operation '%s': Credential store is set non modifiable")
    CredentialStoreException nonModifiableCredentialStore(String operation);

    @Message(id = 9507, value = "Invalid protection parameter given: %s")
    CredentialStoreException invalidProtectionParameter(CredentialStore.ProtectionParameter protectionParameter);

    @Message(id = 9508, value = "Cannot write credential to store")
    CredentialStoreException cannotWriteCredentialToStore(@Cause Throwable cause);

    @Message(id = 9509, value = "Unsupported credential type %s")
    UnsupportedCredentialTypeException unsupportedCredentialType(Class<?> type);

    @Message(id = 9510, value = "Invalid credential store keystore entry %s: expected %s")
    CredentialStoreException invalidCredentialStoreEntryType(Class<? extends KeyStore.Entry> entryType,
            Class<? extends KeyStore.Entry> expectedType);

    @Message(id = 9511, value = "Unable to read credential %s from store")
    CredentialStoreException unableToReadCredentialTypeFromStore(Class<? extends Credential> credentialType);

    @Message(id = 9512, value = "Unable to remove credential from store")
    CredentialStoreException cannotRemoveCredentialFromStore(@Cause Throwable cause);

    @Message(id = 9513, value = "Unable to flush credential store to storage")
    CredentialStoreException cannotFlushCredentialStore(@Cause Throwable cause);

    @Message(id = 9514, value = "Unable to initialize credential store")
    CredentialStoreException cannotInitializeCredentialStore(@Cause Throwable cause);

    @Message(id = 9515, value = "Ignored unrecognized key store entry \"%s\"")
    @LogMessage(level = DEBUG)
    void logIgnoredUnrecognizedKeyStoreEntry(String alias);

    @Message(id = 9516, value = "Failed to read a credential entry from the key store")
    @LogMessage(level = WARN)
    void logFailedToReadKeyFromKeyStore(@Cause Throwable cause);

    @Message(id = 9517, value = "This credential store type requires a store-wide protection parameter")
    CredentialStoreException protectionParameterRequired();

    @Message(id = 9518, value = "Automatic storage creation for the Credential Store is disabled \"%s\"")
    CredentialStoreException automaticStorageCreationDisabled(String location);

    @Message(id = 9519, value = "Unexpected credential store external storage file version \"%s\"")
    IOException unexpectedFileVersion(String version);

    @Message(id = 9520, value = "Unrecognized entry type \"%s\"")
    IOException unrecognizedEntryType(String entryType);

    @Message(id = 9521, value = "Internal encryption problem while reading \"%s\"")
    IOException internalEncryptionProblem(@Cause Exception e, String location);

    @Message(id = 9522, value = "\"%s\" is not a block based algorithm")
    CredentialStoreException algorithmNotBlockBased(String algorithm);

    @Message(id = 9523, value = "Algorithm \"%s\" does not use an initialization vector (IV)")
    CredentialStoreException algorithmNotIV(String algorithm);

    @Message(id = 9524, value = "The actual number of bytes read %d is different from the expected number of bytes %d to be read")
    IOException readBytesMismatch(int actual, int expected);

    @Message(id = 9525, value = "location and externalPath initial attributes are the same. [location=%s, externalPath=%s]")
    CredentialStoreException locationAndExternalPathAreIdentical(String location, String externalPath);

    @Message(id = 9526, value = "Unable to initialize credential store as attribute %s is unsupported in %s")
    CredentialStoreException unsupportedAttribute(String attribute, List<String> validAttribute);

    @Message(id = 9528, value = "The externalPath attribute for key store type %s is missing.")
    CredentialStoreException externalPathMissing(String keyStoreType);

    @Message(id = 11006, value = "External storage key under alias \"%s\" does not exist")
    CredentialStoreException externalStorageKeyDoesNotExist(String keyAlias);

    @Message(id = 12000, value = "The credential store file %s does not exist or cannot be accessed.")
    CredentialStoreException credentialStoreFileDoesNotExist(String fileLocation);

}
