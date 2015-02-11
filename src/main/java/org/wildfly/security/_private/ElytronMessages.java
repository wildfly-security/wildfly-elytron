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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

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
import org.wildfly.client.config.ConfigXMLParseException;

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

    @Message(value = "Parse error")
    String parseError();

    // id = 2

    // id = 3

    // id = 4

    // id = 5

    // id = 6

    @Message(id = 7, value = "Invalid port number \"%s\" specified for attribute \"%s\" of element \"%s\"; expected a numerical value between 1 and 65535 (inclusive)")
    ConfigXMLParseException xmlInvalidPortNumber(@Param XMLStreamReader reader, String attributeValue, String attributeName, QName elementName);

    // id = 8

    // id = 9

    // id = 10

    @Message(id = 11, value = "%s is null")
    IllegalArgumentException nullParameter(String parameter);

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

    @Message(id = 21, value = "SASL exchange received a message after authentication was already complete")
    SaslException saslMessageAfterComplete();

    @Message(id = 22, value = "SASL user name contains an invalid or disallowed character")
    SaslException saslUserNameContainsInvalidCharacter();

    @Message(id = 23, value = "SASL user name could not be decoded from encoding \"%s\"")
    SaslException saslUserNameDecodeFailed(String encodingName);

    @Message(id = 24, value = "SASL authorization failed")
    SaslException saslAuthorizationFailed(@Cause Throwable cause);

    @Message(id = 25, value = "SASL authentication is not yet complete")
    IllegalStateException saslAuthenticationNotComplete();

    @Message(id = 26, value = "No SASL security layer is currently in force")
    SaslException saslNoSecurityLayer();

    @Message(id = 27, value = "Invalid SASL negotiation message received")
    SaslException saslInvalidMessageReceived();

    @Message(id = 28, value = "SASL client-side authentication failed")
    SaslException saslClientSideAuthenticationFailed(@Cause Exception e);

    @Message(id = 29, value = "No SASL login name was given")
    SaslException saslNoLoginNameGiven();

    @Message(id = 30, value = "No SASL password was given")
    SaslException saslNoPasswordGiven();

    @Message(id = 31, value = "SASL authentication failed due to one or more malformed fields")
    SaslException saslMalformedFields(@Cause IllegalArgumentException ex);

    @Message(id = 32, value = "SASL message is too long")
    SaslException saslMessageTooLong();

    @Message(id = 33, value = "SASL server-side authentication failed")
    SaslException saslServerSideAuthenticationFailed(@Cause Exception e);

    @Message(id = 34, value = "SASL password not verified")
    SaslException saslPasswordNotVerified();

    @Message(id = 35, value = "SASL authorization failed: \"%s\" is not authorized to act on behalf of \"%s\"")
    SaslException saslAuthorizationFailed(String loginName, String authorizationId);

    @Message(id = 36, value = "Unexpected character U+%04x at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnexpectedChar(int codePoint, int offset, String string);

    @Message(id = 37, value = "Unrecognized token \"%s\" in mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnknownToken(String word, String string);

    @Message(id = 38, value = "Token \"%s\" not allowed at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorTokenNotAllowed(String token, int offset, String string);

    @Message(id = 39, value = "Expected token \"%s\" at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorTokenExpected(String token, int offset, String string);

    @Message(id = 40, value = "Proxied SASL authentication failed")
    SaslException saslProxyAuthenticationFailed();

    @Message(id = 41, value = "No SASL client mechanism \"%s\" is available with the current configuration from %s")
    SaslException saslNoClientMechanism(String mechName, SaslClientFactory clientFactory);

    @Message(id = 42, value = "No SASL server mechanism \"%s\" is available with the current configuration from %s")
    SaslException saslNoServerMechanism(String mechName, SaslServerFactory serverFactory);
}
