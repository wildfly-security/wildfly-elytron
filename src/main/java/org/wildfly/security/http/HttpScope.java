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

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * An attachment scope for use by an authentication mechanism, different scopes may be available to share Objects e.g.
 * Application, Session, Connection.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface HttpScope {

    // TODO - We may want to add 'exists' and 'create' methods but probably most specifically related to sessions.
    /**
     * Does this scope support attachments?
     *
     * @return {@code true} if this scope supports attachments, {@code false} otherwise}
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

}
