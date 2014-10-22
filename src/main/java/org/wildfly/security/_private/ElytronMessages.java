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

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.Param;
import org.wildfly.security.auth.ElytronXMLParseException;

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

    @Message(id = 2, value = "Invalid URI \"%s\" specified for attribute \"%s\" of element \"%s\"")
    ElytronXMLParseException xmlInvalidUri(@Param XMLStreamReader reader, String attributeValue, String attributeName, QName elementName);

    @Message(id = 3, value = "Missing required attribute \"%s\" of element \"%s\"")
    ElytronXMLParseException xmlMissingRequiredAttribute(@Param XMLStreamReader reader, String attributeName, QName name);

    @Message(id = 4, value = "Unexpected end of XML document")
    ElytronXMLParseException xmlUnexpectedDocumentEnd(@Param XMLStreamReader reader);

    @Message(id = 5, value = "Unexpected content")
    ElytronXMLParseException xmlUnexpectedContent(@Param XMLStreamReader reader);

    @Message(id = 6, value = "Unexpected empty document")
    ElytronXMLParseException xmlEmptyDocument(@Param XMLStreamReader reader);

    @Message(id = 7, value = "Invalid port number \"%s\" specified for attribute \"%s\" of element \"%s\"; expected a numerical value between 1 and 65535 (inclusive)")
    ElytronXMLParseException xmlInvalidPortNumber(@Param XMLStreamReader reader, String attributeValue, String attributeName, QName elementName);

    @Message(id = 8, value = "Unexpected attribute \"%s\" encountered in element \"%s\"")
    ElytronXMLParseException xmlUnexpectedAttribute(@Param XMLStreamReader reader, String attributeName, QName elementName);

    @Message(id = 9, value = "Configuration file \"%s\" not found")
    ElytronXMLParseException xmlFileNotFound(String file);

    @Message(id = 10, value = "Failed to load configuration file \"%s\"")
    ElytronXMLParseException xmlFailedToLoad(@Cause Throwable cause, String fileName);

    @Message(id = 11, value = "%s is null")
    IllegalArgumentException nullParameter(String parameter);

    @Message(id = 12, value = "Realm map does not contain mapping for default realm '%s'")
    IllegalArgumentException realmMapDoesntContainDefault(String defaultRealm);

    @Message(id = 13, value = "This builder has already been built")
    IllegalStateException builderAlreadyBuilt();

}
