/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.server.event;

import org.jboss.logmanager.handlers.SyslogHandler;
import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * A security audit event indicating that a log with RFC 3164 syslog format is occurring
 *
 * @author <a href="mailto:jucook@redhat.com">Justin Cook</a>
 */
public class Rfc3164SyslogEvent extends SyslogAuditEvent {

    /**
     * Constructor for a new instance.
     *
     * @param securityIdentity the {@link SecurityIdentity} that corresponds to this event that is to be logged with RFC3164
     */
    public Rfc3164SyslogEvent(SecurityIdentity securityIdentity){
        super(securityIdentity, SyslogHandler.SyslogType.RFC3164);
    }
}
