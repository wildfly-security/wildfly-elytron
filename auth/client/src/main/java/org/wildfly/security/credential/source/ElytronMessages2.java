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

package org.wildfly.security.credential.source;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

import org.wildfly.security.mechanism.AuthenticationMechanismException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
interface ElytronMessages2 extends BasicLogger {

    ElytronMessages2 saslOAuth2 = Logger.getMessageLogger(ElytronMessages2.class, "org.wildfly.security.sasl.oauth2");

    @Message(id = 1106, value = "Could not obtain SSLContext")
    IllegalStateException failedToObtainSSLContext(@Cause Throwable cause);

    @Message(id = 5053, value = "Callback handler failed for unknown reason")
    AuthenticationMechanismException mechCallbackHandlerFailedForUnknownReason(@Cause Throwable cause);

    @Message(id = 5125, value = "Unable to handle response from server")
    AuthenticationMechanismException mechUnableToHandleResponseFromServer(@Cause Throwable cause);

    @Message(id = 9001, value = "Client credentials not provided")
    IllegalStateException oauth2ClientCredentialsNotProvided();
}
