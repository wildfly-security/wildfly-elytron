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
 * An immutable view of a cached single sign-on entry.
 * @author Paul Ferraro
 */
public interface ImmutableSingleSignOn {
    /**
     * Returns the unique identifier of this single sign-on entry.
     * @return a unique identifier
     */
    String getId();

    /**
     * Returns the authentication mechanism associated with this single sign-on entry.
     * @return an authentication mechanism name
     */
    String getMechanism();

    /**
     * Returns the name of the principal associated with this single sign-on entry.
     * @return a principal name
     */
    String getName();

    /**
     * Returns the transient security identity associated with this single sign-on entry.
     * @return a security identity, or null if this entry was created by another node.
     */
    SecurityIdentity getIdentity();

    /**
     * Returns the participants associated with this single sign-on entry.
     * @return an unmodifiable mapping of application identifier to a tuple of the session identifier and request URI
     */
    Map<String, Map.Entry<String, URI>> getParticipants();
}
