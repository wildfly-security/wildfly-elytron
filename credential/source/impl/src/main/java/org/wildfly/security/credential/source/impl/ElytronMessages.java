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

package org.wildfly.security.credential.source.impl;

import java.io.IOException;
import java.io.InterruptedIOException;

import javax.security.sasl.SaslException;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages saslOAuth2 = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.oauth2");

    @Message(id = 1030, value = "Unable to read credential")
    IOException unableToReadCredential(@Cause Exception e);

    @Message(id = 5053, value = "Callback handler failed for unknown reason")
    SaslException mechCallbackHandlerFailedForUnknownReason(@Cause Throwable cause);

    @Message(id = 5125, value = "Unable to handle response from server")
    SaslException mechUnableToHandleResponseFromServer(@Cause Throwable cause);

    @Message(id = 9506, value = "Credential store command interrupted")
    InterruptedIOException credentialCommandInterrupted();

    @Message(id = 9511, value = "Unable to read credential %s from store")
    CredentialStoreException unableToReadCredentialTypeFromStore(Class<? extends Credential> credentialType);

}
