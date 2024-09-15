/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.dynamic.ssl;

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
        @ValidIdRange(min = 21000, max = 21999)
})
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 21000, value = "DynamicSSLContext creates loop")
    IllegalStateException dynamicSSLContextCreatesLoop();

    @Message(id = 21001, value = "Received SSLContext from DynamicSSLContextProvider was null")
    IllegalStateException receivedSSLContextFromDynamicSSLContextProviderWasNull();

    @Message(id = 21002, value = "Dynamic SSLContext does not support sessions")
    UnsupportedOperationException dynamicSSLContextDoesNotSupportSessions();

    @Message(id = 21003, value = "Provider for DynamicSSLContextSPI threw an exception when getting configured SSLContexts")
    IllegalStateException unableToGetConfiguredSSLContexts();

    @Message(id = 21004, value = "Provider for DynamicSSLContextSPI returned null configured SSLContexts")
    IllegalStateException configuredSSLContextsAreNull();

    @Message(id = 21005, value = "Cannot obtain default SSLContext from DynamicSSLContext implementation")
    IllegalStateException cannotObtainConfiguredDefaultSSLContext();

    @Message(id = 21006, value = "Could not create URI from host and port")
    IllegalStateException couldNotCreateURI();

    @Message(id = 21007, value = "Could not create dynamic ssl context engine")
    IllegalStateException couldNotCreateDynamicSSLContextEngine();

    @Message(id = 21008, value = "Provider for DynamicSSLContextSPI returned null SSLContext")
    IllegalStateException configuredSSLContextIsNull();

    @Message(id = 21009, value = "Obtaining of the default SSLContext from current authentication context resulted in exception.")
    DynamicSSLContextException cannotObtainDefaultSSLContext(@Cause Throwable cause);

    @Message(id = 21010, value = "Obtaining of all configured SSLContexts from current authentication context resulted in exception.")
    DynamicSSLContextException cannotObtainConfiguredSSLContexts(@Cause Throwable cause);

    @Message(id = 21011, value = "Obtaining of the SSLContext from current authentication context and provided URI resulted in exception.")
    DynamicSSLContextException cannotObtainSSLContextForGivenURI(@Cause Throwable cause);
}
