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

package org.wildfly.security.auth.client;

import static org.jboss.logging.Logger.Level.WARN;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

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

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages xmlLog = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.xml");
    
    @Message(id = 1001, value = "No module found for identifier \"%s\"")
    ConfigXMLParseException xmlNoModuleFound(@Param XMLStreamReader reader, @Cause Exception e, String moduleIdentifier);
    
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
    ConfigXMLParseException xmlDuplicateAuthenticationConfigurationName(String name, @Param ConfigurationXMLStreamReader reader);
    
    @Message(id = 1135, value = "Failed to load keystore data")
    ConfigXMLParseException xmlFailedToLoadKeyStoreData(@Param Location location, @Cause Throwable cause);
    
    @Message(id = 1139, value = "Failed to create credential store")
    ConfigXMLParseException xmlFailedToCreateCredentialStore(@Param Location location, @Cause Throwable cause);

    @Message(id = 1140, value = "Wrong PEM content type; expected %s, actually was %s")
    ConfigXMLParseException xmlWrongPemType(@Param ConfigurationXMLStreamReader reader, Class<?> expected, Class<?> actual);
    
    @Message(id = 1141, value = "No PEM content found")
    ConfigXMLParseException xmlNoPemContent(@Param ConfigurationXMLStreamReader reader);
    
    @Message(id = 1164, value = "Unable to identify provider name=%s, for service type=%s, algorithm=%s")
    ConfigXMLParseException xmlUnableToIdentifyProvider(@Param Location location, String providerName, String serviceType, String algorithm);
    
    @LogMessage(level = WARN)
    @Message(id = 1166, value = "%2$s: Element \"%1$s\" is deprecated")
    void xmlDeprecatedElement(String name, XMLLocation location);
    
    @Message(id = 2010, value = "Unknown key store specified")
    ConfigXMLParseException xmlUnknownKeyStoreSpecified(@Param Location location);

    @Message(id = 4005, value = "No default trust manager available")
    NoSuchAlgorithmException noDefaultTrustManager();
    
    @Message(id = 4028, value = "No default key manager available")
    NoSuchAlgorithmException noDefaultKeyManager();
    
    
}
