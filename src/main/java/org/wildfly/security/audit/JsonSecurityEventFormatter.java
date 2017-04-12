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
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.function.Supplier;

import javax.json.Json;
import javax.json.JsonObjectBuilder;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.event.SecurityAuthenticationFailedEvent;
import org.wildfly.security.auth.server.event.SecurityDefiniteOutcomeEvent;
import org.wildfly.security.auth.server.event.SecurityEvent;
import org.wildfly.security.auth.server.event.SecurityEventVisitor;
import org.wildfly.security.auth.server.event.SecurityPermissionCheckEvent;

/**
 * A formatter for security events that converts the event to a JSON String.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class JsonSecurityEventFormatter extends SecurityEventVisitor<Void, String> {

    private final Supplier<DateFormat> dateFormatSupplier;

    /**
     *
     */
    JsonSecurityEventFormatter(Builder builder) {
        this.dateFormatSupplier = builder.dateFormatSupplier;
    }

    @Override
    public String handleUnknownEvent(SecurityEvent event, Void param) {
        checkNotNullParam("event", event);
        JsonObjectBuilder objectBuilder = Json.createObjectBuilder();
        handleUnknownEvent(event, objectBuilder);
        return objectBuilder.build().toString();
    }

    private void handleUnknownEvent(SecurityEvent event, JsonObjectBuilder objectBuilder) {
        DateFormat dateFormat = dateFormatSupplier.get();

        objectBuilder.add("event", event.getClass().getSimpleName());
        objectBuilder.add("event-time", dateFormat.format(Date.from(event.getInstant())));

        JsonObjectBuilder securityIdentityBuilder = Json.createObjectBuilder();
        SecurityIdentity securityIdentity = event.getSecurityIdentity();
        securityIdentityBuilder.add("name", securityIdentity.getPrincipal().getName());
        securityIdentityBuilder.add("creation-time", dateFormat.format(Date.from(securityIdentity.getCreationTime())));

        objectBuilder.add("security-identity", securityIdentityBuilder);
    }

    @Override
    public String handleDefiniteOutcomeEvent(SecurityDefiniteOutcomeEvent event, Void param) {
        checkNotNullParam("event", event);
        JsonObjectBuilder objectBuilder = Json.createObjectBuilder();
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
        JsonObjectBuilder objectBuilder = Json.createObjectBuilder();
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
        JsonObjectBuilder objectBuilder = Json.createObjectBuilder();
        handlePermissionCheckEvent(event, objectBuilder);
        return objectBuilder.build().toString();
    }

    private void handlePermissionCheckEvent(SecurityPermissionCheckEvent event, JsonObjectBuilder objectBuilder) {
        handleDefiniteOutcomeEvent(event, objectBuilder);

        Permission permission = event.getPermission();
        JsonObjectBuilder permissionBuilder = Json.createObjectBuilder();
        permissionBuilder.add("type", permission.getClass().getName());
        permissionBuilder.add("actions", permission.getActions());
        permissionBuilder.add("name", permission.getName());

        objectBuilder.add("permission", permissionBuilder);
    }

    /**
     * Create a new builder.
     *
     * @return a new builder.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private Supplier<DateFormat> dateFormatSupplier = SimpleDateFormat::new;

        Builder() {
        }

        /**
         * Set a {@link Supplier<DateFormat>} to format any dates in the resulting output.
         *
         * @param dateFormatSupplier a {@link Supplier<DateFormat>} to format any dates in the resulting output.
         * @return {@code this} builder.
         */
        public Builder setDateFormatSupplier(Supplier<DateFormat> dateFormatSupplier) {
            this.dateFormatSupplier = checkNotNullParam("dateFormatSupplier", dateFormatSupplier);

            return this;
        }

        /**
         * Build a new {@link SecurityEventVisitor} which will convert {@link SecurityEvent} instances into JSON formatted
         * Strings.
         *
         * Once built the Builder can continue to be configured to create additional instances.
         *
         * @return a new {@link SecurityEventVisitor} which will convert {@link SecurityEvent} instances into JSON formatted
         *         Strings.
         */
        public SecurityEventVisitor<?, String> build() {
            return new JsonSecurityEventFormatter(this);
        }

    }

}
