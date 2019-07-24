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

package org.wildfly.security.authz.jacc;

import static org.jboss.logging.Logger.Level.DEBUG;
import static org.jboss.logging.Logger.Level.ERROR;

import java.security.Permission;
import java.security.ProtectionDomain;

import javax.security.jacc.PolicyContextException;

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
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 3018, max = 3018),
    @ValidIdRange(min = 8500, max = 8508)
})
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    /* authz package */

    @Message(id = 3018, value = "Cannot add permissions to a read-only permission collection")
    SecurityException readOnlyPermissionCollection();

    @LogMessage(level = ERROR)
    @Message(id = 8500, value = "Failed to check permissions for protection domain [%s] and permission [%s].")
    void authzFailedToCheckPermission(ProtectionDomain domain, Permission permission, @Cause Throwable cause);

    @Message(id = 8501, value = "Invalid state [%s] for operation.")
    UnsupportedOperationException authzInvalidStateForOperation(String actualState);

    @Message(id = 8502, value = "Can't link policy configuration [%s] to itself.")
    IllegalArgumentException authzLinkSamePolicyConfiguration(String contextID);

    @Message(id = 8503, value = "ContextID not set. Check if the context id was set using PolicyContext.setContextID.")
    IllegalStateException authzContextIdentifierNotSet();

    @Message(id = 8504, value = "Invalid policy context identifier [%s].")
    IllegalArgumentException authzInvalidPolicyContextIdentifier(String contextID);

    @Message(id = 8505, value = "Could not obtain PolicyConfiguration for contextID [%s].")
    PolicyContextException authzUnableToObtainPolicyConfiguration(String contextId, @Cause Throwable cause);

    @Message(id = 8506, value = "Policy configuration with contextID [%s] is not in service state.")
    IllegalStateException authzPolicyConfigurationNotInService(String contextID);

    // @LogMessage(level = ERROR)
    // @Message(id = 8507, value = "Could not obtain dynamic permissions.")
    // void authzFailedGetDynamicPermissions(@Cause Throwable cause);

    @LogMessage(level = DEBUG)
    @Message(id = 8508, value = "Could not obtain authorized identity.")
    void authzCouldNotObtainSecurityIdentity(@Cause Throwable cause);

}
