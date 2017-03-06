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

import java.net.URI;
import java.util.Map;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * A cached single sign-on entry.
 * @author Paul Ferraro
 */
public interface SingleSignOn extends ImmutableSingleSignOn, AutoCloseable {

    /**
     * Associates a security identity with this single sign-on entry, only if no association exists.
     * @param identity a security identity
     */
    void setIdentity(SecurityIdentity identity);

    /**
     * Adds a new participant to this single sign-on entry.
     * @param applicationId the unique identifier of the application.
     * @param sessionId the unique identifier of the user session.
     * @param participant the authenticated request URI
     * @return true, if this participant was added, false if this application is already associated with this single sign-on entry.
     */
    boolean addParticipant(String applicationId, String sessionId, URI participant);

    /**
     * Removes the participant for the specified application from this single sign-on entry.
     * @param applicationId a unique application identifier
     * @return a tuple containing the unique session identifier and authenticated request URI, or null if the specified application was not associated with this single sign-on entry
     */
    Map.Entry<String, URI> removeParticipant(String applicationId);

    /**
     * Invalidates this single sign-on entry.
     */
    void invalidate();

    /**
     * Closes any resources associated with this single sign-on entry.
     */
    @Override
    void close();
}
