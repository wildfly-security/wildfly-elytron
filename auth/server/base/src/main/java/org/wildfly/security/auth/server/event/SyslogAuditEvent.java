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
 * An abstract class to be extended by specific syslog audit events to be handled.
 *
 * @author <a href="mailto:jucook@redhat.com">Justin Cook</a>
 */
public abstract class SyslogAuditEvent extends SecurityEvent {
    private SyslogHandler.SyslogType format;

    /**
     * Constructor for a new instance.
     *
     * @param securityIdentity the {@link SecurityIdentity} that corresponds to this event that is to be logged
     * @param format The syslog format that is to be used for this event
     */
    SyslogAuditEvent(SecurityIdentity securityIdentity, SyslogHandler.SyslogType format) {
        super(securityIdentity);
        this.format = format;
    }

    /**
     * Gets the syslog format that is to be used for this audit event
     *
     * @return The syslog format
     */
    public SyslogHandler.SyslogType getFormat() {
        return format;
    }

    /**
     * Accept the given visitor, calling the method which is most applicable to this event type.
     *
     * @param visitor the visitor
     * @param param the parameter to pass to the visitor {@code handleXxx} method
     * @param <P> the visitor parameter type
     * @param <R> the visitor return type
     * @return the value returned from the visitor {@code handleXxx} method
     */
    public <P, R> R accept(SecurityEventVisitor<P, R> visitor, P param) {
        return visitor.handleSyslogAuditEvent(this, param);
    }
}
