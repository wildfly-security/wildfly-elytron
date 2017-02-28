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

import static org.wildfly.common.Assert.checkNotNullParam;

import java.net.URI;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Collections;
import java.util.Map;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;

/**
 * {@link SignleSignOn} implementation backed by a {@link DefaultSingleSignOnEntry}.
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author Paul Ferraro
 */
public class DefaultSingleSignOn implements SingleSignOn {
    private final String id;
    private final SingleSignOnEntry entry;
    private final Runnable mutator;
    private final Runnable remover;

    public DefaultSingleSignOn(String id, SingleSignOnEntry entry, Runnable mutator, Runnable remover) {
        this.id = checkNotNullParam("id", id);
        this.entry = checkNotNullParam("entry", entry);
        this.mutator = checkNotNullParam("mutator", mutator);
        this.remover = checkNotNullParam("remover", remover);
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public String getMechanism() {
        return this.entry.getCachedIdentity().getMechanismName();
    }

    @Override
    public String getName() {
        return this.entry.getCachedIdentity().getName();
    }

    @Override
    public SecurityIdentity getIdentity() {
        return this.entry.getCachedIdentity().getSecurityIdentity();
    }

    @Override
    public void setIdentity(SecurityIdentity identity) {
        // Only set cached identity if it has not already been set
        synchronized (this.entry) {
            CachedIdentity cached = this.entry.getCachedIdentity();
            if (cached.getSecurityIdentity() == null) {
                this.entry.setCachedIdentity(new CachedIdentity(cached.getMechanismName(), identity));
            }
        }
    }

    @Override
    public boolean addParticipant(String applicationId, String sessionId, URI participant) {
        boolean added = this.entry.getParticipants().putIfAbsent(applicationId, new SimpleImmutableEntry<>(sessionId, participant)) == null;
        if (added) {
            this.mutator.run();
        }
        return added;
    }

    @Override
    public Map.Entry<String, URI> removeParticipant(String applicationId) {
        Map.Entry<String, URI> removed = this.entry.getParticipants().remove(applicationId);
        if (removed != null) {
            this.mutator.run();
        }
        return removed;
    }

    @Override
    public Map<String, Map.Entry<String, URI>> getParticipants() {
        return Collections.unmodifiableMap(this.entry.getParticipants());
    }

    @Override
    public void invalidate() {
        this.remover.run();
    }

    @Override
    public void close() {
        // Do nothing
    }
}
