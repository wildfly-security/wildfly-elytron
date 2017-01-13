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

import java.util.concurrent.ConcurrentMap;
import java.util.function.BiConsumer;
import java.util.function.Supplier;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;

/**
 * {@link SingleSignOnManager} based on a {@link ConcurrentMap} of {@link DefaultSingleSignOnEntry} instances.
 * @author Paul Ferraro
 */
public class DefaultSingleSignOnManager implements SingleSignOnManager {
    private final ConcurrentMap<String, SingleSignOnEntry> cache;
    private final BiConsumer<String, SingleSignOnEntry> mutator;
    private final Supplier<String> identifierFactory;

    public DefaultSingleSignOnManager(ConcurrentMap<String, SingleSignOnEntry> cache, Supplier<String> identifierFactory) {
        this(cache, identifierFactory, (id, entry) -> {});
    }

    public DefaultSingleSignOnManager(ConcurrentMap<String, SingleSignOnEntry> cache, Supplier<String> identifierFactory, BiConsumer<String, SingleSignOnEntry> mutator) {
        this.cache = checkNotNullParam("cache", cache);
        this.mutator = checkNotNullParam("mutator", mutator);
        this.identifierFactory = checkNotNullParam("identifierFactory", identifierFactory);
    }

    @Override
    public SingleSignOn create(String mechanismName, SecurityIdentity identity) {
        String id = this.identifierFactory.get();
        SingleSignOnEntry entry = new DefaultSingleSignOnEntry(new CachedIdentity(mechanismName, identity));
        SingleSignOn sso = new DefaultSingleSignOn(id, entry, () -> this.mutator.accept(id, entry), () -> this.cache.remove(id));
        this.cache.put(id, entry);
        return sso;
    }

    @Override
    public SingleSignOn find(String id) {
        SingleSignOnEntry entry = this.cache.get(id);
        return (entry != null) ? new DefaultSingleSignOn(id, entry, () -> this.mutator.accept(id, entry), () -> this.cache.remove(id)) : null;
    }
}
