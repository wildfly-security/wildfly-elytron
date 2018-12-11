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
package org.wildfly.security.http.util.sso;

import org.wildfly.security.cache.IdentityCache;

/**
 * Represents a single sign-on session.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @see SingleSignOnSessionFactory
 */
public interface SingleSignOnSession extends IdentityCache, AutoCloseable {

    /**
     * The identifier associated with this session.
     *
     * @return identifier associated with this session
     */
    String getId();

    /**
     * Performs a local logout where only the local session is invalidated.
     *
     * @return {@code true} if local session was invalidated. Otherwise, {@code false}
     */
    boolean logout();

    /**
     * Closes any resources associated with this single sign-on session.
     */
    @Override
    void close();
}