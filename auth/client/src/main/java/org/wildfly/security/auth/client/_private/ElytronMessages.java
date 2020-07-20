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

package org.wildfly.security.auth.client._private;

import static org.jboss.logging.Logger.Level.WARN;

import java.io.IOException;
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
        @ValidIdRange(min = 1001, max = 1002),
        @ValidIdRange(min = 1028, max = 1029),
        @ValidIdRange(min = 1035, max = 1036),
        @ValidIdRange(min = 1041, max = 1041),
        @ValidIdRange(min = 1064, max = 1064),
        @ValidIdRange(min = 1091, max = 1091),
        @ValidIdRange(min = 1129, max = 1144),
        @ValidIdRange(min = 1159, max = 1159),
        @ValidIdRange(min = 1162, max = 1164),
        @ValidIdRange(min = 1166, max = 1166),
        @ValidIdRange(min = 2034, max = 2034),
        @ValidIdRange(min = 2010, max = 2010),
        @ValidIdRange(min = 4005, max = 4005),
        @ValidIdRange(min = 4028, max = 4028),
        @ValidIdRange(min = 9501, max = 9503),
        @ValidIdRange(min = 9527, max = 9527),
        @ValidIdRange(min = 9529, max = 9529),
        @ValidIdRange(min = 14000, max = 14999)
})
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages xmlLog = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.xml");

    @Message(id = 1001, value = "No module found for identifier \"%s\"")
    ConfigXMLParseException xmlNoModuleFound(@Param XMLStreamReader reader, @Cause Exception e,
            String moduleIdentifier);

    @Message(id = 1002, value = "Invalid port number \"%s\" specified for attribute \"%s\" of element \"%s\"; expected a numerical value between 1 and 65535 (inclusive)")
    ConfigXMLParseException xmlInvalidPortNumber(@Param XMLStreamReader reader, String attributeValue,
            String attributeName, QName elementName);

    @Message(id = 1028, value = "Invalid port number \"%d\"")
    IllegalArgumentException invalidPortNumber(int port);

    @Message(id = 1029, value = "Invalid host specification \"%s\"")
    IllegalArgumentException invalidHostSpec(String hostSpec);

    @Message(id = 1035, value = "Unable to create key manager")
    IOException unableToCreateKeyManager(@Cause Exception e);

    @Message(id = 1036, value = "Unable to create trust manager")
    IOException unableToCreateTrustManager(@Cause Exception e);

    @Message(id = 1041, value = "Could not obtain credential")
    RuntimeException couldNotObtainCredential();

    @Message(id = 1064, value = "Invalid identity name")
    IllegalArgumentException invalidName();

    @LogMessage(level = WARN)
    @Message(id = 1091, value = "Post-association peer context action failed")
    void postAssociationFailed(@Cause Throwable cause);

    @Message(id = 1129, value = "Unknown SSL context \"%s\" specified")
    ConfigXMLParseException xmlUnknownSslContextSpecified(@Param Location location, String name);

    @Message(id = 1130, value = "Duplicate SSL context name \"%s\"")
    ConfigXMLParseException xmlDuplicateSslContextName(String name, @Param ConfigurationXMLStreamReader reader);

    @Message(id = 1132, value = "Unknown authentication configuration \"%s\" specified")
    ConfigXMLParseException xmlUnknownAuthenticationConfigurationSpecified(@Param Location location, String name);

    @Message(id = 1133, value = "Failed to create credential")
    ConfigXMLParseException xmlFailedToCreateCredential(@Param Location location, @Cause Throwable cause);

    @Message(id = 1134, value = "Duplicate authentication configuration name \"%s\"")
    ConfigXMLParseException xmlDuplicateAuthenticationConfigurationName(String name,
            @Param ConfigurationXMLStreamReader reader);

    @Message(id = 1135, value = "Failed to load keystore data")
    ConfigXMLParseException xmlFailedToLoadKeyStoreData(@Param Location location, @Cause Throwable cause);

    @Message(id = 1136, value = "Failed to create keystore")
    ConfigXMLParseException xmlFailedToCreateKeyStore(@Param Location location, @Cause Throwable cause);

    @Message(id = 1137, value = "Invalid key store entry type for alias \"%s\" (expected %s, got %s)")
    ConfigXMLParseException xmlInvalidKeyStoreEntryType(@Param Location location, String alias, Class<?> expectedClass,
            Class<?> actualClass);

    @Message(id = 1139, value = "Failed to create credential store")
    ConfigXMLParseException xmlFailedToCreateCredentialStore(@Param Location location, @Cause Throwable cause);

    @Message(id = 1140, value = "Wrong PEM content type; expected %s, actually was %s")
    ConfigXMLParseException xmlWrongPemType(@Param ConfigurationXMLStreamReader reader, Class<?> expected,
            Class<?> actual);

    @Message(id = 1141, value = "No PEM content found")
    ConfigXMLParseException xmlNoPemContent(@Param ConfigurationXMLStreamReader reader);

    @Message(id = 1143, value = "Invalid URL [%s]")
    ConfigXMLParseException xmlInvalidUrl(String url);

    @Message(id = 1159, value = "Key store entry for alias \"%s\" is missing.")
    ConfigXMLParseException keyStoreEntryMissing(@Param Location location, String alias);

    @Message(id = 1162, value = "Invalid GSS mechanism name \"%s\" - unable to convert to mechanism OID")
    ConfigXMLParseException xmlInvalidGssMechanismName(@Param XMLStreamReader reader, String mechanismName);

    @Message(id = 1163, value = "Mechanism OID conversion from string \"%s\" failed")
    ConfigXMLParseException xmlGssMechanismOidConversionFailed(@Param XMLStreamReader reader, String mechanismOid,
            @Cause Throwable cause);

    @Message(id = 1164, value = "Unable to identify provider name=%s, for service type=%s, algorithm=%s")
    ConfigXMLParseException xmlUnableToIdentifyProvider(@Param Location location, String providerName,
            String serviceType, String algorithm);

    @LogMessage(level = WARN)
    @Message(id = 1166, value = "%2$s: Element \"%1$s\" is deprecated")
    void xmlDeprecatedElement(String name, XMLLocation location);

    @Message(id = 2034, value = "Alias must be specified if more than one entry exist in keystore")
    ConfigXMLParseException missingAlias(@Param Location location);

    @Message(id = 2010, value = "Unknown key store specified")
    ConfigXMLParseException xmlUnknownKeyStoreSpecified(@Param Location location);

    @Message(id = 4005, value = "No default trust manager available")
    NoSuchAlgorithmException noDefaultTrustManager();

    @Message(id = 4028, value = "No default key manager available")
    NoSuchAlgorithmException noDefaultKeyManager();

    @Message(id = 9501, value = "Duplicate attribute (\"%s\") found in configuration.")
    ConfigXMLParseException duplicateAttributeFound(@Param XMLStreamReader reader, String attribute);

    @Message(id = 9502, value = "Duplicate credential store name found in configuration \"%s\"")
    ConfigXMLParseException duplicateCredentialStoreName(@Param XMLStreamReader reader, String storeName);

    @Message(id = 9503, value = "Credential store name \"%s\" not defined")
    ConfigXMLParseException xmlCredentialStoreNameNotDefined(@Param Location location, String storeName);

    @Message(id = 9527, value = "Invalid credential store reference")
    ConfigXMLParseException xmlInvalidCredentialStoreRef(@Param Location location);

    @Message(id = 9529, value = "Unsupported algorithm \"%s\" for %s type")
    ConfigXMLParseException xmlUnsupportedAlgorithmForType(@Param Location location, String algorithm, String type);

    @Message(id = 14000, value = "At least one of the '%s' and '%s' cipher-suite attributes must be provided")
    ConfigXMLParseException atLeastOneCipherSuiteAttributeMustBeProvided(String attribute1, String attribute2);

    @Message(id = 14001, value = "Wrong Key content type; expected OpenSSH private key")
    ConfigXMLParseException xmlInvalidOpenSSHKey(@Param ConfigurationXMLStreamReader reader);

    @Message(id = 14002, value = "Unable to obtain SSLContext")
    ConfigXMLParseException unableToObtainSslContext();

    @Message(id = 14003, value = "Name callback handling was unsuccessful")
    ConfigXMLParseException nameCallbackHandlingWasUnsuccessful();

    @Message(id = 14004, value = "Password callback handling was unsuccessful")
    ConfigXMLParseException passwordCallbackHandlingWasUnsuccessful();
}
