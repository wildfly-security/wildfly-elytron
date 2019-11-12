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

package org.wildfly.security.auth.server._private;

import static org.jboss.logging.Logger.Level.ERROR;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Principal;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.Param;

import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.AuthorizationFailureException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 3, max = 3),
    @ValidIdRange(min = 8, max = 8),
    @ValidIdRange(min = 1000, max = 1156),
    @ValidIdRange(min = 8510, max = 8511),
    @ValidIdRange(min = 16000, max = 16999)
})
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 3, value = "This builder has already been built")
    IllegalStateException builderAlreadyBuilt();

    @Message(id = 8, value = "The given credential is not supported here")
    IllegalArgumentException credentialNotSupported();

    @Message(id = 1000, value = "Authentication name was already set on this context")
    IllegalStateException nameAlreadySet();

    @Message(id = 1003, value = "No authentication is in progress")
    IllegalStateException noAuthenticationInProgress();

    @Message(id = 1005, value = "Realm map does not contain mapping for default realm '%s'")
    IllegalArgumentException realmMapDoesNotContainDefault(String defaultRealm);

    @Message(id = 1019, value = "Unable to obtain exclusive access to backing identity")
    RealmUnavailableException unableToObtainExclusiveAccess();

    @Message(id = 1033, value = "User does not exist")
    IllegalStateException userDoesNotExist();

    @Message(id = 1034, value = "Invalid credential type specified")
    IllegalStateException invalidCredentialTypeSpecified();

    @Message(id = 1064, value = "Invalid identity name")
    IllegalArgumentException invalidName();

    @Message(id = 1088, value = "Attempting to run as \"%s\" authorization operation failed")
    AuthorizationFailureException runAsAuthorizationFailed(@Param Principal principal, Principal targetPrincipal,
            @Cause Throwable cause);

    @Message(id = 1092, value = "Invalid mechanism realm selection \"%s\"")
    IllegalArgumentException invalidMechRealmSelection(String realmName);

    @Message(id = 1093, value = "Mechanism realm was already selected")
    IllegalStateException mechRealmAlreadySelected();

    @Message(id = 1095, value = "Unable to create identity")
    RealmUnavailableException unableToCreateIdentity();

    @Message(id = 1096, value = "No such identity")
    RealmUnavailableException noSuchIdentity();

    @Message(id = 1112, value = "Authentication cannot succeed; not authorized")
    IllegalStateException cannotSucceedNotAuthorized();

    @Message(id = 1119, value = "Unable to resolve MechanismConfiguration for mechanismType='%s', mechanismName='%s', hostName='%s', protocol='%s'.")
    IllegalStateException unableToSelectMechanismConfiguration(String mechanismType, String mechanismName,
            String hostName, String protocol);

    @Message(id = 1120, value = "Too late to set mechanism information as authentication has already begun.")
    IllegalStateException tooLateToSetMechanismInformation();

    @Message(id = 1124, value = "The security realm does not support updating a credential")
    UnsupportedOperationException credentialUpdateNotSupportedByRealm();

    @Message(id = 1148, value = "A SecurityDomain has already been associated with the specified ClassLoader")
    IllegalStateException classLoaderSecurityDomainExists();

    @Message(id = 1149, value = "Can not use SecurityIdentity with SecurityIdentity from same SecurityDomain")
    IllegalArgumentException cantWithSameSecurityDomainDomain();

    @Message(id = 1151, value = "Evidence Verification Failed.")
    SecurityException authenticationFailedEvidenceVerification();

    @Message(id = 1152, value = "Authorization Check Failed.")
    SecurityException authenticationFailedAuthorization();

    @Message(id = 1155, value = "Security domain mismatch")
    IllegalArgumentException securityDomainMismatch();

    @Message(id = 1156, value = "Cannot obtain a credential from a security factory")
    IOException cannotObtainCredentialFromFactory(@Cause GeneralSecurityException e);

    @LogMessage(level = ERROR)
    @Message(id = 1094, value = "An event handler threw an exception")
    void eventHandlerFailed(@Cause Throwable cause);

    @Message(id = 8510, value = "Role mapper has already been initialized.")
    IllegalStateException roleMappedAlreadyInitialized();

    @Message(id = 8511, value = "Role mapper hasn't been initialized yet.")
    IllegalStateException roleMappedNotInitialized();

    @Message(id = 16000, value = "Invalid replacement in regex role mapper.")
    IllegalArgumentException invalidReplacementInRegexRoleMapper();

    @Message(id = 16001, value = "Invalid pattern in regex role mapper.")
    IllegalArgumentException invalidPatternInRegexRoleMapper();

    @Message(id = 16002, value = "Can not handle SecurityEvent with SecurityIdentity from other SecurityDomain")
    IllegalArgumentException securityEventIdentityWrongDomain();
}
