/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jose.jwks;

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

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.jose.jwks");

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
