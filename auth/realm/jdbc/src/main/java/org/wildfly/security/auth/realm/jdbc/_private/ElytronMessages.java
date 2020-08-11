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
package org.wildfly.security.auth.realm.jdbc._private;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;
import org.wildfly.security.auth.server.RealmUnavailableException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */

@ValidIdRanges({
    @ValidIdRange(min = 1043, max = 1052)
})@MessageLogger(projectCode = "ELY", length = 5)
public interface ElytronMessages extends BasicLogger {
    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 1043, value = "Invalid password key specification for algorithm \"%s\"")
    RuntimeException invalidPasswordKeySpecificationForAlgorithm(String algorithm, @Cause Throwable cause);

    @Message(id = 1045, value = "Could not obtain PasswordFactory for algorithm \"%s\"")
    RuntimeException couldNotObtainPasswordFactoryForAlgorithm(String algorithm, @Cause Throwable cause);

    @Message(id = 1049, value = "Could not open connection")
    RealmUnavailableException couldNotOpenConnection(@Cause Throwable cause);

    @Message(id = 1050, value = "Could not execute query \"%s\"")
    RealmUnavailableException couldNotExecuteQuery(String sql, @Cause Throwable cause);

    @Message(id = 1052, value = "Unexpected error when processing authentication query \"%s\"")
    RealmUnavailableException unexpectedErrorWhenProcessingAuthenticationQuery(String sql, @Cause Throwable cause);
}
