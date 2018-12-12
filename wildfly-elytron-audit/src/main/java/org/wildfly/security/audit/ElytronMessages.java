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
package org.wildfly.security.audit;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
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
    ElytronMessages audit = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.audit");

    /* Audit Exceptions */

    // 11000 - Unused in any Final release

    @LogMessage(level = Logger.Level.FATAL)
    @Message(id = 11001, value = "Endpoint unable to handle SecurityEvent priority=%s, message=%s")
    void endpointUnavaiable(String priority, String message, @Cause Throwable cause);

    @Message(id = 11002, value = "Invalid EventPriority '%s' passed to AuditEndpoint.")
    IllegalArgumentException invalidEventPriority(EventPriority eventPriority);

    @LogMessage(level = Logger.Level.ERROR)
    @Message(id = 11003, value = "Unable to rotate log file")
    void unableToRotateLogFile( @Cause Throwable cause);

    @Message(id = 11004, value = "Invalid suffix \"%s\" - rotating by second or millisecond is not supported")
    IllegalArgumentException rotatingBySecondUnsupported(String suffix);

    @LogMessage(level = Logger.Level.FATAL)
    @Message(id = 11007, value = "Endpoint unable to accept SecurityEvent.")
    void unableToAcceptEvent(@Cause Throwable cause);
}
