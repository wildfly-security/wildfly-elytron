/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http;

/**
 * Interface providing information about scope notifications.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface HttpScopeNotification extends HttpServerScopes {

    /**
     * {@link Scope#SESSION} notification types
     */
    enum SessionNotificationType {
        INVALIDATED, TIMEOUT, UNDEPLOY
    }

    /**
     * Returns {@code true} if this notification matches any of the specified types.
     *
     * @param types the notification types to check
     * @return {@code true} if this notification matches any of the specified types. Otherwise {@code false}
     */
    boolean isOfType(Enum... types);
}
