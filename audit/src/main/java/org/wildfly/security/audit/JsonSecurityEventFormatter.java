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

import javax.json.JsonObjectBuilder;
import javax.json.spi.JsonProvider;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.event.SecurityAuthenticationFailedEvent;
import org.wildfly.security.auth.server.event.SecurityDefiniteOutcomeEvent;
import org.wildfly.security.auth.server.event.SecurityEvent;
import org.wildfly.security.auth.server.event.SecurityEventVisitor;
import org.wildfly.security.auth.server.event.SecurityPermissionCheckEvent;
import org.wildfly.security.auth.server.event.SecurityRealmUnavailableEvent;
import org.wildfly.security.auth.server.event.SyslogAuditEvent;

/**
 * A formatter for security events that converts events into JSON strings.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class JsonSecurityEventFormatter extends SecurityEventVisitor<Void, String> {

    private final Supplier<DateTimeFormatter> dateTimeFormatterSupplier;

    private final JsonProvider jsonProvider;

    JsonSecurityEventFormatter(Builder builder) {
        this.dateTimeFormatterSupplier = builder.dateTimeFormatterSupplier;
        this.jsonProvider = JsonProvider.provider();
    }

    @Override
    public String handleUnknownEvent(SecurityEvent event, Void param) {
        checkNotNullParam("event", event);
        JsonObjectBuilder objectBuilder = jsonProvider.createObjectBuilder();
        handleUnknownEvent(event, objectBuilder);
        return objectBuilder.build().toString();
    }

    private void handleUnknownEvent(SecurityEvent event, JsonObjectBuilder objectBuilder) {
        DateTimeFormatter dateFormat = dateTimeFormatterSupplier.get();

        objectBuilder.add("event", event.getClass().getSimpleName());
        objectBuilder.add("event-time", dateFormat.format(event.getInstant()));

        JsonObjectBuilder securityIdentityBuilder = jsonProvider.createObjectBuilder();
        SecurityIdentity securityIdentity = event.getSecurityIdentity();
        securityIdentityBuilder.add("name", securityIdentity.getPrincipal().getName());
        securityIdentityBuilder.add("creation-time", dateFormat.format(securityIdentity.getCreationTime()));

        objectBuilder.add("security-identity", securityIdentityBuilder);
    }

    @Override
    public String handleDefiniteOutcomeEvent(SecurityDefiniteOutcomeEvent event, Void param) {
        checkNotNullParam("event", event);
        JsonObjectBuilder objectBuilder = jsonProvider.createObjectBuilder();
        handleDefiniteOutcomeEvent(event, objectBuilder);
        return objectBuilder.build().toString();
    }

    private void handleDefiniteOutcomeEvent(SecurityDefiniteOutcomeEvent event, JsonObjectBuilder objectBuilder) {
        handleUnknownEvent(event, objectBuilder);
        objectBuilder.add("success", event.isSuccessful());
    }

    @Override
    public String handleAuthenticationFailedEvent(SecurityAuthenticationFailedEvent event, Void param) {
        checkNotNullParam("event", event);
        JsonObjectBuilder objectBuilder = jsonProvider.createObjectBuilder();
        handleAuthenticationFailedEvent(event, objectBuilder);
        return objectBuilder.build().toString();
    }

    private void handleAuthenticationFailedEvent(SecurityAuthenticationFailedEvent event, JsonObjectBuilder objectBuilder) {
        handleDefiniteOutcomeEvent(event, objectBuilder);
        if (event.getPrincipal() != null && event.getPrincipal().toString() != null) {
            objectBuilder.add("principal", event.getPrincipal().toString());
        } else {
            objectBuilder.addNull("principal");
        }
    }

    @Override
    public String handlePermissionCheckEvent(SecurityPermissionCheckEvent event, Void param) {
        checkNotNullParam("event", event);
        JsonObjectBuilder objectBuilder = jsonProvider.createObjectBuilder();
        handlePermissionCheckEvent(event, objectBuilder);
        return objectBuilder.build().toString();
    }

    private void handlePermissionCheckEvent(SecurityPermissionCheckEvent event, JsonObjectBuilder objectBuilder) {
        handleDefiniteOutcomeEvent(event, objectBuilder);

        Permission permission = event.getPermission();
        JsonObjectBuilder permissionBuilder = jsonProvider.createObjectBuilder();
        permissionBuilder.add("type", permission.getClass().getName());
        permissionBuilder.add("actions", permission.getActions());
        permissionBuilder.add("name", permission.getName());

        objectBuilder.add("permission", permissionBuilder);
    }

    @Override
    public String handleSyslogAuditEvent(SyslogAuditEvent event, Void param) {
        checkNotNullParam("event", event);
        JsonObjectBuilder objectBuilder = jsonProvider.createObjectBuilder();
        handleSyslogAuditEvent(event, objectBuilder);
        return objectBuilder.build().toString();
    }

    private void handleSyslogAuditEvent(SyslogAuditEvent event, JsonObjectBuilder objectBuilder) {
        handleUnknownEvent(event, objectBuilder);
        objectBuilder.add("syslog-format", event.getFormat().toString());
    }

    @Override
    public String handleRealmUnavailableEvent(SecurityRealmUnavailableEvent event, Void param) {
        checkNotNullParam("event", event);
        JsonObjectBuilder objectBuilder = jsonProvider.createObjectBuilder();
        handleRealmUnavailableEvent(event, objectBuilder);
        return objectBuilder.build().toString();
    }

    private void handleRealmUnavailableEvent(SecurityRealmUnavailableEvent event, JsonObjectBuilder objectBuilder) {
        handleUnknownEvent(event, objectBuilder);
        objectBuilder.add("realm-name", event.getRealmName());
    }

    /**
     * Obtain a new {@link Builder} capable of building a {@link JsonSecurityEventFormatter}.
     *
     * @return a new {@link Builder} capable of building a {@link JsonSecurityEventFormatter}
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for JSON security event formatter.
     */
    public static class Builder {

        private Supplier<DateTimeFormatter> dateTimeFormatterSupplier = () -> DateTimeFormatter.ofLocalizedDateTime(FormatStyle.SHORT).withZone(ZoneId.systemDefault());

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
         * Build a new {@link SecurityEventVisitor} which will convert events into JSON formatted strings.
         * <p>
         * Once built the Builder can continue to be configured to create additional instances.
         *
         * @return a new {@link SecurityEventVisitor} which will convert events into JSON formatted strings
         */
        public SecurityEventVisitor<?, String> build() {
            return new JsonSecurityEventFormatter(this);
        }

    }

}
