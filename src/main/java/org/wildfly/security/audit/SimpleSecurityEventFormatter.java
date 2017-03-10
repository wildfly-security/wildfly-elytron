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

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.event.SecurityAuthenticationFailedEvent;
import org.wildfly.security.auth.server.event.SecurityDefiniteOutcomeEvent;
import org.wildfly.security.auth.server.event.SecurityEvent;
import org.wildfly.security.auth.server.event.SecurityEventVisitor;
import org.wildfly.security.auth.server.event.SecurityPermissionCheckEvent;

/**
 * A formatter for security events that converts the event to a simple String.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SimpleSecurityEventFormatter extends SecurityEventVisitor<Void, String> {

    private final Supplier<DateFormat> dateFormatSupplier;

    /**
     *
     */
    SimpleSecurityEventFormatter(Builder builder) {
        this.dateFormatSupplier = builder.dateFormatSupplier;
    }

    @Override
    public String handleUnknownEvent(SecurityEvent event, Void param) {
        checkNotNullParam("event", event);
        StringBuilder stringBuilder = new StringBuilder('{');
        handleUnknownEvent(event, stringBuilder);
        return stringBuilder.append('}').toString();
    }

    private void handleUnknownEvent(SecurityEvent event, StringBuilder stringBuilder) {
        DateFormat dateFormat = dateFormatSupplier.get();
        stringBuilder.append("event=").append(event.getClass().getSimpleName());
        stringBuilder.append(",event-time=").append(dateFormat.format(Date.from(event.getInstant())));

        SecurityIdentity securityIdentity = event.getSecurityIdentity();
        stringBuilder.append(",security-identity=[name=").append(securityIdentity.getPrincipal().getName());
        stringBuilder.append(",creation-time=").append(dateFormat.format(Date.from(securityIdentity.getCreationTime()))).append(']');
    }


    @Override
    public String handleDefiniteOutcomeEvent(SecurityDefiniteOutcomeEvent event, Void param) {
        checkNotNullParam("event", event);
        StringBuilder stringBuilder = new StringBuilder('{');
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
        StringBuilder stringBuilder = new StringBuilder('{');
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
        StringBuilder stringBuilder = new StringBuilder('{');
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
         * Build a new {@link SecurityEventVisitor} which will convert {@link SecurityEvent} instances into a simple String
         *
         * Once built the Builder can continue to be configured to create additional instances.
         *
         * @return a new {@link SecurityEventVisitor} which will convert {@link SecurityEvent} instances into a simple String
         *         Strings.
         */
        public SecurityEventVisitor<Void, String> build() {
            return new SimpleSecurityEventFormatter(this);
        }

    }

}
