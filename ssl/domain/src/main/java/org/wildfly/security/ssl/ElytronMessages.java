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

package org.wildfly.security.ssl;

import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;
import org.wildfly.security.auth.server.RealmUnavailableException;

import java.security.Principal;
import java.security.cert.CertificateException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @apiNote This interface complements {@code BaseElytronMessages} from module {@code wildfly-elytron-ssl-base} with messages
 * for security domains. The interfaces share message IDs, and they should always be modified together.
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 1066, max = 1077),
    @ValidIdRange(min = 4001, max = 4031),
    @ValidIdRange(min = 5015, max = 5017),
    @ValidIdRange(min = 15000, max = 15999)
})
interface ElytronMessages extends BaseElytronMessages {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages tls = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.tls");

    @Message(id = 4002, value = "Empty certificate chain is not trusted")
    CertificateException emptyChainNotTrusted();

    @Message(id = 4003, value = "Certificate not trusted due to realm failure for principal [%s]")
    CertificateException notTrustedRealmProblem(@Cause RealmUnavailableException e, Principal principal);

    @Message(id = 4004, value = "Credential validation failed: certificate is not trusted for principal [%s]")
    CertificateException notTrusted(Principal principal);

    @Message(id = 4027, value = "SecurityDomain of SSLContext does not support X509PeerCertificateChainEvidence verification")
    IllegalArgumentException securityDomainOfSSLContextDoesNotSupportX509();

}
