/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.oidc.jwks;

import static org.jboss.logging.Logger.Level.DEBUG;
import static org.jboss.logging.Logger.Level.ERROR;
import static org.jboss.logging.Logger.Level.TRACE;

import java.net.URL;
import java.util.Set;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;


/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
        @ValidIdRange(min = 25000, max = 25999)
})
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.oidc.jwks");

    @LogMessage(level = DEBUG)
    @Message(id = 25000, value = "JWKS fetch rate-limited for URL '%s' (last fetch at %d ms)")
    void jwksRateLimited(URL url, long lastFetchTimeMs);

    @LogMessage(level = ERROR)
    @Message(id = 25001, value = "Failed to fetch JWKS from URL '%s'")
    void jwksFetchFailed(URL url, @Cause Throwable cause);

    @LogMessage(level = TRACE)
    @Message(id = 25002, value = "Sending request to retrieve JWKS from URL '%s'")
    void jwksFetchStarting(URL url);

    @LogMessage(level = DEBUG)
    @Message(id = 25003, value = "JWKS successfully retrieved from URL '%s'. Kids: %s")
    void jwksFetchSucceeded(URL url, Set<String> kids);

}
