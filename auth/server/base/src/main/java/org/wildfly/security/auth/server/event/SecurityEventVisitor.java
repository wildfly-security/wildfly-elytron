/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

/**
 * An abstract class to be extended by visitor implementations for handling SecurityEvents.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class SecurityEventVisitor<P, R> {

    /**
     * Construct a security event visitor.
     */
    protected SecurityEventVisitor() {
    }

    /**
     * Handle any unhandled security event.
     *
     * @param event the security event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleUnknownEvent(final SecurityEvent event, final P param) {
        return null;
    }

    /**
     * Handle a security definite outcome event.
     *
     * @param event the security event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleDefiniteOutcomeEvent(final SecurityDefiniteOutcomeEvent event, final P param) {
        return handleUnknownEvent(event, param);
    }

    /**
     * Handle a security authentication event.
     *
     * @param event the security event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleAuthenticationEvent(final SecurityAuthenticationEvent event, final P param) {
        return handleDefiniteOutcomeEvent(event, param);
    }

    /**
     * Handle a security authentication successful event.
     *
     * @param event the security event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleAuthenticationSuccessfulEvent(final SecurityAuthenticationSuccessfulEvent event, final P param) {
        return handleAuthenticationEvent(event, param);
    }

    /**
     * Handle a security authentication failed event.
     *
     * @param event the security event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleAuthenticationFailedEvent(final SecurityAuthenticationFailedEvent event, final P param) {
        return handleAuthenticationEvent(event, param);
    }

    /**
     * Handle a security permission check event.
     *
     * @param event the security event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handlePermissionCheckEvent(final SecurityPermissionCheckEvent event, final P param) {
        return handleDefiniteOutcomeEvent(event, param);
    }

    /**
     * Handle a security permission check successful event.
     *
     * @param event the security event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handlePermissionCheckSuccessfulEvent(final SecurityPermissionCheckSuccessfulEvent event, final P param) {
        return handlePermissionCheckEvent(event, param);
    }

    /**
     * Handle a security permission check failed event.
     *
     * @param event the security event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handlePermissionCheckFailedEvent(final SecurityPermissionCheckFailedEvent event, final P param) {
        return handlePermissionCheckEvent(event, param);
    }

    /**
     * Handle an auditable event that is to be logged to syslog.
     *
     * @param event the security event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleSyslogAuditEvent(final SyslogAuditEvent event, final P param) {
        return handleUnknownEvent(event, param);
    }

    /**
     * Handle a security realm unavailable event.
     *
     * @param event the security event
     * @param param the visitor parameter
     * @return the visitor return value
     */
    public R handleRealmUnavailableEvent(final SecurityRealmUnavailableEvent event, final P param) {
        return handleUnknownEvent(event, param);
    }
}
