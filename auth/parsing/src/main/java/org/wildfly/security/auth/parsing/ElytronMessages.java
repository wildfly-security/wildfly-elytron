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

package org.wildfly.security.auth.parsing;

import static org.jboss.logging.Logger.Level.WARN;

import java.security.NoSuchAlgorithmException;

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

import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.client.config.ConfigurationXMLStreamReader;
import org.wildfly.client.config.XMLLocation;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
        @ValidIdRange(min = 14000, max = 14999)

})
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages xmlLog = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.xml");

    @Message(id = 14000, value = "Invalid port number \"%s\" specified for attribute \"%s\" of element \"%s\"; expected a numerical value between 1 and 65535 (inclusive)")
    ConfigXMLParseException xmlInvalidPortNumber(@Param XMLStreamReader reader, String attributeValue, String attributeName, QName elementName);

    @Message(id = 14001, value = "Could not obtain credential")
    RuntimeException couldNotObtainCredential();

    @Message(id = 14002, value = "Unknown SSL context \"%s\" specified")
    ConfigXMLParseException xmlUnknownSslContextSpecified(@Param Location location, String name);

    @Message(id = 14003, value = "Duplicate SSL context name \"%s\"")
    ConfigXMLParseException xmlDuplicateSslContextName(String name, @Param ConfigurationXMLStreamReader reader);

    @Message(id = 14004, value = "Unknown authentication configuration \"%s\" specified")
    ConfigXMLParseException xmlUnknownAuthenticationConfigurationSpecified(@Param Location location, String name);

    @Message(id = 14005, value = "Failed to create credential")
    ConfigXMLParseException xmlFailedToCreateCredential(@Param Location location, @Cause Throwable cause);

    @Message(id = 14006, value = "Duplicate authentication configuration name \"%s\"")
    ConfigXMLParseException xmlDuplicateAuthenticationConfigurationName(String name,
            @Param ConfigurationXMLStreamReader reader);

    @Message(id = 14007, value = "Failed to load keystore data")
    ConfigXMLParseException xmlFailedToLoadKeyStoreData(@Param Location location, @Cause Throwable cause);

    @Message(id = 14008, value = "Failed to create keystore")
    ConfigXMLParseException xmlFailedToCreateKeyStore(@Param Location location, @Cause Throwable cause);

    @Message(id = 14009, value = "Wrong PEM content type; expected %s, actually was %s")
    ConfigXMLParseException xmlWrongPemType(@Param ConfigurationXMLStreamReader reader, Class<?> expected,
            Class<?> actual);

    @Message(id = 14010, value = "No PEM content found")
    ConfigXMLParseException xmlNoPemContent(@Param ConfigurationXMLStreamReader reader);

    @Message(id = 14011, value = "Invalid URL [%s]")
    ConfigXMLParseException xmlInvalidUrl(String url);

    @Message(id = 14012, value = "Key store entry for alias \"%s\" is missing.")
    ConfigXMLParseException keyStoreEntryMissing(@Param Location location, String alias);

    @Message(id = 14013, value = "Invalid GSS mechanism name \"%s\" - unable to convert to mechanism OID")
    ConfigXMLParseException xmlInvalidGssMechanismName(@Param XMLStreamReader reader, String mechanismName);

    @Message(id = 14014, value = "Mechanism OID conversion from string \"%s\" failed")
    ConfigXMLParseException xmlGssMechanismOidConversionFailed(@Param XMLStreamReader reader, String mechanismOid,
            @Cause Throwable cause);

    @Message(id = 14015, value = "Unable to identify provider name=%s, for service type=%s, algorithm=%s")
    ConfigXMLParseException xmlUnableToIdentifyProvider(@Param Location location, String providerName,
            String serviceType, String algorithm);

    @LogMessage(level = WARN)
    @Message(id = 14016, value = "%2$s: Element \"%1$s\" is deprecated")
    void xmlDeprecatedElement(String name, XMLLocation location);

    @Message(id = 14017, value = "Alias must be specified if more than one entry exist in keystore")
    ConfigXMLParseException missingAlias(@Param Location location);

    @Message(id = 14018, value = "Unknown key store specified")
    ConfigXMLParseException xmlUnknownKeyStoreSpecified(@Param Location location);

    @Message(id = 14019, value = "No default trust manager available")
    NoSuchAlgorithmException noDefaultTrustManager();

    @Message(id = 14020, value = "No default key manager available")
    NoSuchAlgorithmException noDefaultKeyManager();

    @Message(id = 14021, value = "Duplicate attribute (\"%s\") found in configuration.")
    ConfigXMLParseException duplicateAttributeFound(@Param XMLStreamReader reader, String attribute);

    @Message(id = 14022, value = "Duplicate credential store name found in configuration \"%s\"")
    ConfigXMLParseException duplicateCredentialStoreName(@Param XMLStreamReader reader, String storeName);

    @Message(id = 14023, value = "Credential store name \"%s\" not defined")
    ConfigXMLParseException xmlCredentialStoreNameNotDefined(@Param Location location, String storeName);

    @Message(id = 14024, value = "Invalid credential store reference")
    ConfigXMLParseException xmlInvalidCredentialStoreRef(@Param Location location);

    @Message(id = 14025, value = "Unsupported algorithm \"%s\" for %s type")
    ConfigXMLParseException xmlUnsupportedAlgorithmForType(@Param Location location, String algorithm, String type);

    @Message(id = 14026, value = "At least one of the '%s' and '%s' cipher-suite attributes must be provided")
    ConfigXMLParseException atLeastOneCipherSuiteAttributeMustBeProvided(String attribute1, String attribute2);

}
