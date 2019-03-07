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

import static org.wildfly.security.http.ElytronMessages.log;

import java.io.InputStream;
import java.util.function.Consumer;

/**
 * An attachment scope for use by an authentication mechanism.
 * <p>
 * Different scopes may be available to share Objects e.g. Application, Session, Connection.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface HttpScope {

    /**
     * Get the ID of this scope or (@code null} if IDs are not supported for this scope or the scope doesn't currently exist.
     *
     * @return the ID of this scope or (@code null} if IDs are not supported for this scope or the scope doesn't currently exist.
     */
    default String getID() {
        return null;
    }

    /**
     * Tests whether this scope exists.
     *
     * @return {@code true} if this scope exists. Otherwise, {@code false}
     */
    default boolean exists() {
        return true;
    }

    /**
     * Create this scope.
     *
     * @return {@code true} if the scope was created. Otherwise, {@code false} indicating that this scope was already created or that creation is not support.
     */
    default boolean create() {
        return false;
    }

    /**
     * Tests whether this scope support attachments.
     *
     * @return {@code true} if this scope supports attachments, {@code false} otherwise
     */
    default boolean supportsAttachments() {
        return false;
    }

    /**
     * Set the named attribute on this scope, setting to {@code null} will clear any value previously set for this key.
     *
     * @param key the key to use to store the attachment.
     * @param value the value to store with the key or {@code null} to clear any previously stored attachment.
     * @throws UnsupportedOperationException if attachments are not supported.
     */
    default void setAttachment(final String key, final Object value) {
        throw log.noAttachmentSupport();
    }

    /**
     * Get the attachment previously associated with the key specified on this scope.
     *
     * @param key the key used to store the attachment on this scope.
     * @return the value associated with the scope or {@code null} if no association exists.
     * @throws UnsupportedOperationException if attachments are not supported.
     */
    default Object getAttachment(final String key) {
        throw log.noAttachmentSupport();
    }

    /**
     * Get the attachment previously associated with the key specified on this scope and cast it to the type specified.
     *
     * This method will only return a value if the attachment exists AND can be cast to the desired type, otherwise it returns
     * {@code null}.
     *
     * @param key the key used to store the attachment on this scope.
     * @param type the desired type of the attachment.
     * @return the value associated with the scope or {@code null} if no association exists or if it could not be converted to
     *         the requested type.
     * @throws UnsupportedOperationException if attachments are not supported.
     */
    default <T> T getAttachment(final String key, final Class<T> type) {
        Object attachment = getAttachment(key);
        if (attachment != null && type.isInstance(attachment)) {
            return type.cast(attachment);
        }
        return null;
    }

    /**
     * Is invalidation supported for this scope?
     *
     * @return {@code true} if this scope supports invalidation, {@code false} otherwise.
     */
    default boolean supportsInvalidation() {
        return false;
    }

    /**
     * Invalidate this scope.
     *
     * @return {@code true} if invalidation was successful, {@code false} otherwise.
     */
    default boolean invalidate() {
        return false;
    }

    /**
     * Tests whether this scope support access to scope specific resources.
     *
     * @return {@code true} if this scope supports access to scope specific resources, {@code false} otherwise.
     */
    default boolean supportsResources() {
        return false;
    }

    /**
     * Get the resource associated with the path specified.
     *
     * @param path the path to the resource.
     * @return the {@link InputStream} of the resource or {@code null} if resources is not supported or the specified resource is not found.
     */
    default InputStream getResource(final String path) {
        return null;
    }

    /**
     * Tests whether this scope support registration to receive notifications.
     *
     * @return {@code true} if this scope supports registration for notifications, {@code false} otherwise.
     */
    default boolean supportsNotifications() {
        return false;
    }

    /**
     * Register a notification consumer to receive notifications from this scope.
     *
     * @param notificationConsumer the consumer to receive notifications from this scope.
     */
    default void registerForNotification(Consumer<HttpScopeNotification> notificationConsumer) {
    }

}
