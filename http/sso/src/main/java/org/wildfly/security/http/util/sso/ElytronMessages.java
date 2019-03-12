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

package org.wildfly.security.http.util.sso;

import static org.jboss.logging.Logger.Level.ERROR;
import static org.jboss.logging.Logger.Level.WARN;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

import org.wildfly.security.http.HttpAuthenticationException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @LogMessage(level = WARN)
    @Message(id = 6008, value = "Failed to logout participant [%s]. Participant will be removed from list of participants but its local session may still be active.")
    void warnHttpMechSsoFailedLogoutParticipant(String url, @Cause Throwable cause);

    @Message(id = 6012, value = "Invalid logout message received for local session [%s]")
    IllegalStateException httpMechSsoInvalidLogoutMessage(String localSessionId);

    @LogMessage(level = ERROR)
    @Message(id = 6013, value = "Failed to invalidate local session")
    void errorHttpMechSsoFailedInvalidateLocalSession(@Cause Throwable cause);

    @Message(id = 6014, value = "Authentication mechanism '%s' cannot be found")
    HttpAuthenticationException httpServerAuthenticationMechanismNotFound(String mechanismName);
}

