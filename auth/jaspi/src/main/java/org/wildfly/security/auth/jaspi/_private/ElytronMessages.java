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

package org.wildfly.security.auth.jaspi._private;

import java.io.IOException;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 1167, max = 1177)
})
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 1167, value = "Unable to construct provider '%s'.")
    SecurityException unableToConstructProvider(String className, @Cause Throwable cause);

    @Message(id = 1168, value = "JASPIC Configuration for messageLayer=%s, and applicationContext=%s already registered.")
    IllegalStateException configAlreadyRegistered(String messageLayer, String applicationContext);

    @Message(id = 1169, value = "Message type '%s' is not supported by authentication module '%s'")
    IllegalArgumentException unsupportedMessageType(String messageType, String authenticationModule);

    @Message(id = 1170, value = "Unrecognised authContextId '%s'")
    AuthException unrecognisedAuthContextId(String authContextId);

    @Message(id = 1171, value = "Invalid message type '%s', expected '%s'.")
    IllegalArgumentException invalidMessageType(String actualMessageType, String expectedMessageType);

    @Message(id = 1172, value = "Message does not wrap existing message of type '%s'")
    IllegalArgumentException messageDoesNotWrapExistingMessage(String messageType);

    @Message(id = 1173, value = "Message does not un-wrap existing message of type '%s'")
    IllegalArgumentException messageDoesNotUnWrapExistingMessage(String messageType);

    @Message(id = 1174, value = "Setting message of type '%s' not allowed at this time.")
    IllegalStateException messageSettingNotAllowed(String messageType);

    @Message(id = 1175, value = "The wrapping or request / response messages is only allowed where AuthStatus==SUCCESS ServerAuthenticationModule=%s")
    IllegalStateException messageWrappedWithoutSuccess(String module);

    @Message(id = 1176, value = "Invalid AuthStatus %s returned from ServerAuthModule %s.")
    IllegalStateException invalidAuthStatus(AuthStatus authStatus, String serverAuthModule);

    @Message(id = 1177, value = "Authorization failed.")
    IOException authorizationFailed();

}
