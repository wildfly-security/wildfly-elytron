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

package org.wildfly.security.http;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages httpUserPass = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.password");
    ElytronMessages httpClientCert = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.cert");
    
    @Message(id = 6000, value = "Status code can not be set at this time.")
    IllegalStateException statusCodeNotNow();
    
    @Message(id = 6005, value= "Attachments are not supported on this scope.")
    UnsupportedOperationException noAttachmentSupport();

    @Message(id = 6016, value = "HTTP authentication failed validating request, no mechanisms remain to continue authentication.")
    HttpAuthenticationException httpAuthenticationFailedEvaluatingRequest();
    
    @Message(id = 6017, value = "HTTP authentication is required but no authentication mechansims are available.")
    HttpAuthenticationException httpAuthenticationNoMechanisms();

    @Message(id = 6018, value = "HTTP authentication none of the responders successfuly sent a response.")
    HttpAuthenticationException httpAuthenticationNoSuccessfulResponder();
    
}
