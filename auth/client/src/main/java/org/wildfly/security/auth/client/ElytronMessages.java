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

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
        @ValidIdRange(min = 1001, max = 1001),
        @ValidIdRange(min = 1028, max = 1029),
        @ValidIdRange(min = 1035, max = 1036),
        @ValidIdRange(min = 1064, max = 1064),
        @ValidIdRange(min = 1091, max = 1091),
        @ValidIdRange(min = 1139, max = 1139),
})
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages xmlLog = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.xml");

    @Message(id = 1001, value = "No module found for identifier \"%s\"")
    ConfigXMLParseException xmlNoModuleFound(@Param XMLStreamReader reader, @Cause Exception e,
                                             String moduleIdentifier);

    @Message(id = 1028, value = "Invalid port number \"%d\"")
    IllegalArgumentException invalidPortNumber(int port);

    @Message(id = 1029, value = "Invalid host specification \"%s\"")
    IllegalArgumentException invalidHostSpec(String hostSpec);

    @Message(id = 1035, value = "Unable to create key manager")
    IOException unableToCreateKeyManager(@Cause Exception e);

    @Message(id = 1036, value = "Unable to create trust manager")
    IOException unableToCreateTrustManager(@Cause Exception e);

    @Message(id = 1064, value = "Invalid identity name")
    IllegalArgumentException invalidName();

    @LogMessage(level = WARN)
    @Message(id = 1091, value = "Post-association peer context action failed")
    void postAssociationFailed(@Cause Throwable cause);

    @Message(id = 1139, value = "Failed to create credential store")
    ConfigXMLParseException xmlFailedToCreateCredentialStore(@Param Location location, @Cause Throwable cause);

}
