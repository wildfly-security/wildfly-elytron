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
package org.wildfly.security.audit;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.security.Permission;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.function.Supplier;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.event.SecurityAuthenticationFailedEvent;
import org.wildfly.security.auth.server.event.SecurityDefiniteOutcomeEvent;
import org.wildfly.security.auth.server.event.SecurityEvent;
import org.wildfly.security.auth.server.event.SecurityEventVisitor;
import org.wildfly.security.auth.server.event.SecurityPermissionCheckEvent;
import org.wildfly.security.auth.server.event.SecurityRealmUnavailableEvent;
import org.wildfly.security.auth.server.event.SyslogAuditEvent;

/**
 * A formatter for security events that converts events into human-readable strings.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SimpleSecurityEventFormatter extends SecurityEventVisitor<Void, String> {

    private final Supplier<DateTimeFormatter> dateFormatSupplier;

    SimpleSecurityEventFormatter(Builder builder) {
        this.dateFormatSupplier = builder.dateTimeFormatterSupplier;
    }

    @Override
    public String handleUnknownEvent(SecurityEvent event, Void param) {
        checkNotNullParam("event", event);
        StringBuilder stringBuilder = new StringBuilder("{");
        handleUnknownEvent(event, stringBuilder);
        return stringBuilder.append('}').toString();
    }

    private void handleUnknownEvent(SecurityEvent event, StringBuilder stringBuilder) {
        DateTimeFormatter dateFormat = dateFormatSupplier.get();

        stringBuilder.append("event=").append(event.getClass().getSimpleName());
        stringBuilder.append(",event-time=").append(dateFormat.format(event.getInstant()));

        SecurityIdentity securityIdentity = event.getSecurityIdentity();
        stringBuilder.append(",security-identity=[name=").append(securityIdentity.getPrincipal().getName());
        stringBuilder.append(",creation-time=").append(dateFormat.format(securityIdentity.getCreationTime())).append(']');
    }


    @Override
    public String handleDefiniteOutcomeEvent(SecurityDefiniteOutcomeEvent event, Void param) {
        checkNotNullParam("event", event);
        StringBuilder stringBuilder = new StringBuilder("{");
        handleDefiniteOutcomeEvent(event, stringBuilder);
        return stringBuilder.append('}').toString();
    }

    private void handleDefiniteOutcomeEvent(SecurityDefiniteOutcomeEvent event, StringBuilder stringBuilder) {
        handleUnknownEvent(event, stringBuilder);
        stringBuilder.append(",success=").append(event.isSuccessful());
    }

    @Override
    public String handleAuthenticationFailedEvent(SecurityAuthenticationFailedEvent event, Void param) {
        checkNotNullParam("event", event);
        StringBuilder stringBuilder = new StringBuilder("{");
        handleAuthenticationFailedEvent(event, stringBuilder);
        return stringBuilder.append('}').toString();
    }

    private void handleAuthenticationFailedEvent(SecurityAuthenticationFailedEvent event, StringBuilder stringBuilder) {
        handleDefiniteOutcomeEvent(event, stringBuilder);
        stringBuilder.append(",principal=").append(event.getPrincipal() != null ? event.getPrincipal().toString() : null);
    }

    @Override
    public String handlePermissionCheckEvent(SecurityPermissionCheckEvent event, Void param) {
        checkNotNullParam("event", event);
        StringBuilder stringBuilder = new StringBuilder("{");
        handlePermissionCheckEvent(event, stringBuilder);
        return stringBuilder.append('}').toString();
    }

    private void handlePermissionCheckEvent(SecurityPermissionCheckEvent event, StringBuilder stringBuilder) {
        handleDefiniteOutcomeEvent(event, stringBuilder);

        Permission permission = event.getPermission();
        stringBuilder.append(",permission=[type=").append(permission.getClass().getName());
        stringBuilder.append(",actions=").append(permission.getActions());
        stringBuilder.append(",name=").append(permission.getName()).append(']');
    }

    @Override
    public String handleSyslogAuditEvent(SyslogAuditEvent event, Void param) {
        checkNotNullParam("event", event);
        StringBuilder stringBuilder = new StringBuilder("{");
        handleSyslogAuditEvent(event, stringBuilder);
        return stringBuilder.append('}').toString();
    }

    private void handleSyslogAuditEvent(SyslogAuditEvent event, StringBuilder stringBuilder) {
        handleUnknownEvent(event, stringBuilder);
        stringBuilder.append(",syslog-format").append(event.getFormat().toString());
    }

    @Override
    public String handleRealmUnavailableEvent(SecurityRealmUnavailableEvent event, Void param) {
        checkNotNullParam("event", event);
        StringBuilder stringBuilder = new StringBuilder("{");
        handleRealmUnavailableEvent(event, stringBuilder);
        return stringBuilder.append('}').toString();
    }

    private void handleRealmUnavailableEvent(SecurityRealmUnavailableEvent event, StringBuilder stringBuilder) {
        handleUnknownEvent(event, stringBuilder);
        stringBuilder.append(",realm-name=").append(event.getRealmName());
    }

    /**
     * Create a new builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for simple security event formatter.
     */
    public static class Builder {

        private Supplier<DateTimeFormatter> dateTimeFormatterSupplier = ()  -> DateTimeFormatter.ofLocalizedDateTime(FormatStyle.SHORT).withZone(ZoneId.systemDefault());

        Builder() {
        }

        /**
         * Set a supplier of formatter to format any dates in the resulting output.
         * The supplied {@link DateTimeFormatter} has to have a time zone configured.
         *
         * @param dateTimeFormatterSupplier a supplier of formatter to format dates in the resulting output
         * @return this builder
         */
        public Builder setDateTimeFormatterSupplier(Supplier<DateTimeFormatter> dateTimeFormatterSupplier) {
            this.dateTimeFormatterSupplier = checkNotNullParam("dateTimeFormatterSupplier", dateTimeFormatterSupplier);

            return this;
        }

        /**
         * Build a new {@link SecurityEventVisitor} which will convert events into human-readable strings.
         * <p>
         * Once built the Builder can continue to be configured to create additional instances.
         *
         * @return a new {@link SecurityEventVisitor} which will convert events into human-readable strings
         */
        public SecurityEventVisitor<Void, String> build() {
            return new SimpleSecurityEventFormatter(this);
        }

    }

}
