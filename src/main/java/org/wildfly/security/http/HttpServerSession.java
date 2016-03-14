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
 * Represents a HTTP session.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface HttpServerSession {

    /**
     * Returns a string containing the unique identifier assigned to this session. The identifier is assigned
     * by the underlying web container and is implementation dependent.
     *
     * @return a string specifying the identifier assigned to this session
     */
    String getId();

    /**
     * Returns the object bound with the specified name in this session, or <code>null</code> if no object is bound under the name.
     *
     * @param name a string specifying the name of the object
     * @return the object with the specified name
     */
    <R> R getAttribute(String name);

    /**
     * Binds an object to this session, using the name specified. If an object of the same name is already bound to the session,
     * the object is replaced.
     *
     * @param name  the name to which the object is bound
     * @param value the object to be bound
     */
    void setAttribute(String name, Object value);

    /**
     * Removes the object bound with the specified name from this session. If the session does not have an object bound with the specified name,
     * this method does nothing.
     *
     * @param name the name of the object to remove from this session
     */
    <R> R removeAttribute(String name);

    /**
     * Invalidates this session then unbinds any objects bound to it.
     */
    void invalidate();
}
