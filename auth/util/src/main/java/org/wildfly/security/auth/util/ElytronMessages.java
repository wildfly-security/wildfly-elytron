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

package org.wildfly.security.auth.util;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.security.auth.login.LoginException;

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
    @ValidIdRange(min = 3, max = 3),
    @ValidIdRange(min = 1065, max = 1065),
    @ValidIdRange(min = 1121, max = 1123),
    @ValidIdRange(min = 1160, max = 1165),
    @ValidIdRange(min = 3031, max = 3031),
    @ValidIdRange(min = 17000, max = 17999)
})
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 3, value = "This builder has already been built")
    IllegalStateException builderAlreadyBuilt();

    @Message(id = 1065, value = "Pattern requires a capture group")
    IllegalArgumentException patternRequiresCaptureGroup();

    @Message(id = 1121, value = "Unable to perform initial JAAS login.")
    GeneralSecurityException unableToPerformInitialLogin(@Cause LoginException cause);

    @Message(id = 1122, value = "No Kerberos principals found.")
    GeneralSecurityException noKerberosPrincipalsFound();

    @Message(id = 1123, value = "Too many Kerberos principals found.")
    GeneralSecurityException tooManyKerberosPrincipalsFound();

    @Message(id = 1160, value = "KeyTab [%s] does not exists.")
    IOException keyTabDoesNotExists(String keyTab);

    @Message(id = 1161, value = "No keys for Kerberos principal [%s] was found in KeyTab [%s].")
    IOException noKeysForPrincipalInKeyTab(String principal, String keyTab);

    @Message(id = 1165, value = "Initial JAAS login skipped as it has failed in last %d seconds")
    GeneralSecurityException initialLoginSkipped(long seconds);

    @Message(id = 3031, value = "Too many KerberosTicket instances in private credentials")
    GeneralSecurityException tooManyKerberosTicketsFound();

    @Message(id = 17000, value = "Failed to create credential")
    IOException xmlFailedToCreateCredential(@Cause Throwable cause);

}
