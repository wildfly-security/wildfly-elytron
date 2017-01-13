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

import java.io.Serializable;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.wildfly.security.cache.CachedIdentity;

/**
 * Cache entry used by {@link DefaultSingleSignOnManager}.
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author Paul Ferraro
 */
public class DefaultSingleSignOnEntry implements SingleSignOnEntry, Serializable {
    private static final long serialVersionUID = 6051431359445846593L;

    private final ConcurrentMap<String, Map.Entry<String, URI>> participants = new ConcurrentHashMap<>();
    private volatile CachedIdentity cachedIdentity;

    public DefaultSingleSignOnEntry(CachedIdentity cachedIdentity) {
        this.cachedIdentity = checkNotNullParam("cachedIdentity", cachedIdentity);
    }

    @Override
    public CachedIdentity getCachedIdentity() {
        return this.cachedIdentity;
    }

    @Override
    public void setCachedIdentity(CachedIdentity cachedIdentity) {
        this.cachedIdentity = cachedIdentity;
    }

    @Override
    public ConcurrentMap<String, Map.Entry<String, URI>> getParticipants() {
        return this.participants;
    }
}
