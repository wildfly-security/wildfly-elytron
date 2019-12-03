/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.server.event;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * A security event signifying unavailable realm.
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
public class SecurityRealmUnavailableEvent extends SecurityEvent {
    private final String realmName;

    /**
     * Construct a new instance.
     *
     * @param securityIdentity the {@link SecurityIdentity} the permission check was against.
     * @param realmName the unavailable realm name.
     */
    public SecurityRealmUnavailableEvent(SecurityIdentity securityIdentity, String realmName) {
        super(securityIdentity);
        this.realmName = realmName;
    }

    /**
     * Obtain the unavailable realm name.
     *
     * @return the realm name.
     */
    public String getRealmName() {
        return realmName;
    }

    @Override
    public <P, R> R accept(final SecurityEventVisitor<P, R> visitor, final P param) {
        return visitor.handleRealmUnavailableEvent(this, param);
    }
}
