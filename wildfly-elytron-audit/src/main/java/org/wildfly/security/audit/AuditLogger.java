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
import static org.wildfly.security.audit._private.ElytronMessages.audit;

import java.io.IOException;
import java.util.function.Consumer;
import java.util.function.Function;

import org.wildfly.common.function.ExceptionBiConsumer;
import org.wildfly.security.auth.server.event.SecurityEvent;

/**
 * The audit logger implementation.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class AuditLogger implements Consumer<SecurityEvent> {

    private final ExceptionBiConsumer<EventPriority, String, IOException> auditEndpoint;
    private final Function<SecurityEvent, EventPriority> priorityMapper;
    private final Function<SecurityEvent, String> messageFormatter;

    AuditLogger(Builder builder) {
        auditEndpoint = checkNotNullParam("auditEndpoint", builder.auditEndpoint);
        priorityMapper = checkNotNullParam("priorityMapper", builder.priorityMapper);
        messageFormatter = checkNotNullParam("messageFormatter", builder.messageFormatter);
    }

    /**
     * Accept security event to be processed by audit endpoints.
     *
     * @param event security event to be processed
     */
    @Override
    public void accept(SecurityEvent event) {
        try {
            EventPriority priority = priorityMapper.apply(event);
            if (priority == EventPriority.OFF)
                return;

            String formatted = messageFormatter.apply(event);
            try {
                auditEndpoint.accept(priority, formatted);
            } catch (Throwable throwable) {
                audit.endpointUnavaiable(priority.toString(), formatted, throwable);
            }
        } catch (Throwable throwable) {
            audit.unableToAcceptEvent(throwable);
        }
    }

    /**
     * Obtain a new {@link Builder} capable of building a {@link AuditLogger}.
     *
     * @return a new {@link Builder} capable of building a {@link AuditLogger}
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for audit logger instances.
     */
    public static class Builder {

        private ExceptionBiConsumer<EventPriority, String, IOException> auditEndpoint;
        private Function<SecurityEvent, EventPriority> priorityMapper;
        private Function<SecurityEvent, String> messageFormatter;

        Builder() {
        }

        /**
         * Set the endpoint to receive the resulting audit messages.
         *
         * @param auditEndpoint the endpoint to receive the resulting audit messages.
         * @return this builder.
         */
        public Builder setAuditEndpoint(ExceptionBiConsumer<EventPriority, String, IOException> auditEndpoint) {
            this.auditEndpoint = checkNotNullParam("auditEndpoint", auditEndpoint);

            return this;
        }

        /**
         * Set the priority mapper to assign a priority to the messages.
         *
         * @param priorityMapper the priority mapper to assign a priority to the messages.
         * @return this builder.
         */
        public Builder setPriorityMapper(Function<SecurityEvent, EventPriority> priorityMapper) {
            this.priorityMapper = checkNotNullParam("priorityMapper", priorityMapper);

            return this;
        }

        /**
         * Set the message formatter to convert the messages to formatted Strings.
         *
         * @param messageFormatter the message formatter to convert the messages to formatted Strings.
         * @return this builder.
         */
        public Builder setMessageFormatter(Function<SecurityEvent, String> messageFormatter) {
            this.messageFormatter = checkNotNullParam("messageFormatter", messageFormatter);

            return this;
        }

        /**
         * Construct a new audit logger instance.
         *
         * @return the built audit logger.
         */
        public Consumer<SecurityEvent> build() {
            return new AuditLogger(this);
        }

    }

}
