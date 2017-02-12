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

import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

import org.wildfly.security.auth.server.event.SecurityEvent;

/**
 * The audit logger implementation.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class AuditLogger implements Consumer<SecurityEvent> {

    private final BiConsumer<EventPriority, String> auditEndpoint;
    private final Function<SecurityEvent, EventPriority> priorityMapper;
    private final Function<SecurityEvent, String> messageFormatter;

    /**
     *
     */
    AuditLogger(Builder builder) {
        auditEndpoint = checkNotNullParam("auditEndpoint", builder.auditEndpoint);
        priorityMapper = checkNotNullParam("priorityMapper", builder.priorityMapper);
        messageFormatter = checkNotNullParam("messageFormatter", builder.messageFormatter);
    }

    @Override
    public void accept(SecurityEvent t) {
        EventPriority priority = priorityMapper.apply(t);
        if (priority == EventPriority.OFF) return;

        auditEndpoint.accept(priority, messageFormatter.apply(t));
    }

    public static class Builder {

        private BiConsumer<EventPriority, String> auditEndpoint;
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
        public Builder setAuditEndpoint(BiConsumer<EventPriority, String> auditEndpoint) {
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

        public Consumer<SecurityEvent> build() {
            return new AuditLogger(this);
        }

    }

}
