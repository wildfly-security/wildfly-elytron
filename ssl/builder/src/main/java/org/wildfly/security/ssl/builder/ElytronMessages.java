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

package org.wildfly.security.ssl.builder;

import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateException;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;
import org.wildfly.security.auth.server.RealmUnavailableException;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 4001, max = 4031),
    @ValidIdRange(min = 15000, max = 15999)
})
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages tls = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.tls");

    @Message(id = 4002, value = "Empty certificate chain is not trusted")
    CertificateException emptyChainNotTrusted();

    @Message(id = 4003, value = "Certificate not trusted due to realm failure for principal [%s]")
    CertificateException notTrustedRealmProblem(@Cause RealmUnavailableException e, Principal principal);

    @Message(id = 4004, value = "Credential validation failed: certificate is not trusted for principal [%s]")
    CertificateException notTrusted(Principal principal);

    @Message(id = 4005, value = "No default trust manager available")
    NoSuchAlgorithmException noDefaultTrustManager();

    @Message(id = 4006, value = "No context for SSL connection")
    SSLHandshakeException noContextForSslConnection();

    @Message(id = 4007, value = "SSL channel is closed")
    SSLException sslClosed();

    @Message(id = 4024, value = "Invalid client mode, expected %s, got %s")
    IllegalArgumentException invalidClientMode(boolean expectedMode, boolean givenMode);

    @Message(id = 4027, value = "SecurityDomain of SSLContext does not support X509PeerCertificateChainEvidence verification")
    IllegalArgumentException securityDomainOfSSLContextDoesNotSupportX509();

    @Message(id = 15001, value = "No '%s' provided by the configured providers")
    NoSuchAlgorithmException noSslContextProvided(String type);
}
