/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.provider;

import org.wildfly.common.Assert;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.credential.Credential;

import java.util.List;

/**
 * A simple in-memory password-based entry for basic realm implementations.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class SimpleRealmEntry {
    private final List<Credential> credentials;
    private final Attributes attributes;

    /**
     * Construct a new instance.
     *
     * @param credentials the list of credentials (not {@code null})
     */
    public SimpleRealmEntry(final List<Credential> credentials) {
        this(credentials, Attributes.EMPTY);
    }

    /**
     * Construct a new instance.
     *
     * @param credentials the list of credentials (can not be {@code null})
     * @param attributes the entry attributes (can not be {@code null})
     */
    public SimpleRealmEntry(final List<Credential> credentials, final Attributes attributes) {
        Assert.checkNotNullParam("credentials", credentials);
        Assert.checkNotNullParam("attributes", attributes);
        this.credentials = credentials;
        this.attributes = attributes;
    }

    /**
     * Get the credentials for this entry.
     *
     * @return the credentials (not {@code null})
     */
    public List<Credential> getCredentials() {
        return credentials;
    }

    /**
     * Get the entry attributes.
     *
     * @return the entry attributes (not {@code null})
     */
    public Attributes getAttributes() {
        return attributes;
    }
}
