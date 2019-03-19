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

package org.wildfly.security.keystore;

import java.io.EOFException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

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
    ElytronMessages tls = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.tls");

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

    @Message(id = 2035, value = "KeyStore type could not be detected")
    KeyStoreException keyStoreTypeNotDetected();

    @Message(id = 8027, value = "Unknown password type or algorithm")
    InvalidKeyException invalidKeyUnknownUnknownPasswordTypeOrAlgorithm();
}
