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

/**
 * Audit logging related resources.
 *
 * Audit logging registers with the {@link org.wildfly.security.auth.server.SecurityDomain} by registering a
 * {@link java.util.function.Consumer} to receive the emitted {@link org.wildfly.security.auth.server.event.SecurityEvent}s.
 *
 * The audit logging framework is comprised of three core components.
 * <ol>
 * <li>Priority Mapper ({@code Function<SecurityEvent, EventPriority>})</li>
 * <li>Event Formatter ({@code Function<SecurityEvent, String>})</li>
 * <li>Audit Endpoint ({@code ExceptionBiConsumer<EventPriority, String, IOException>})</li>
 * </ol>
 *
 * The priority mapper takes an incoming security event and maps it to one of nine priority levels including a level 'OFF' to
 * cause the event to be immediately discarded.
 *
 * The event formatter takes a security event and converts it to a formatted String ready to be recorded.
 *
 * The audit endpoint is the final component and takes the resulting priority and formatted String to be logged according to the
 * endpoint's configuration.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
package org.wildfly.security.audit;