/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A system of security domains.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SecuritySystem {
    private final ConcurrentMap<String, SecurityDomain> securityDomains = new ConcurrentHashMap<>();

    private static volatile SecuritySystemSelector selector;

    public static SecuritySystem getCurrent() {
        final SecuritySystemSelector selector = SecuritySystem.selector;
        return selector == null ? null : selector.getSecuritySystem();
    }

    public static void setSelector(final SecuritySystemSelector selector) {
        // todo permission check security system selector
        SecuritySystem.selector = selector;
    }

    public SecuritySystem() {
    }

    public SecurityDomain getSecurityDomain(String name) {
        // todo permission check security domain lookup
        return name == null ? null : securityDomains.get(name);
    }

    public void registerSecurityDomain(String name, SecurityDomain securityDomain) {
        if (name == null) {
            throw new IllegalArgumentException("name is null");
        }
        if (securityDomain == null) {
            throw new IllegalArgumentException("securityDomain is null");
        }
        // todo permission check security domain register
        if (securityDomains.putIfAbsent(name, securityDomain) != null) {
            throw new IllegalArgumentException("Duplicate security domain");
        }
    }
}
