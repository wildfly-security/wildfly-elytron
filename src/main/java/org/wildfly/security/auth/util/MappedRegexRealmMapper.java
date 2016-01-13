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

package org.wildfly.security.auth.util;

import java.security.Principal;
import java.util.Map;
import java.util.regex.Pattern;

import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.evidence.Evidence;

/**
 * A simple mapping regular expression-based realm mapper.  The pattern is used to find the realm portion
 * of the user name.  Then, a map is consulted to map this realm portion to an actual configured realm name.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class MappedRegexRealmMapper extends SimpleRegexRealmMapper {
    private final Map<String, String> realmNameMap;

    /**
     * Construct a new instance.
     *
     * @param realmNamePattern the realm name pattern, which must contain at least one capture group (cannot be {@code null})
     * @param realmNameMap the realm portion to realm name map (cannot be {@code null})
     */
    public MappedRegexRealmMapper(final Pattern realmNamePattern, final Map<String, String> realmNameMap) {
        super(realmNamePattern);
        this.realmNameMap = realmNameMap;
    }

    /**
     * Construct a new instance.
     *
     * @param realmNamePattern the realm name pattern, which must contain at least one capture group (cannot be {@code null})
     * @param delegate the delegate mapper to use if the pattern is not matched (cannot be {@code null})
     * @param realmNameMap the realm portion to realm name map (cannot be {@code null})
     */
    public MappedRegexRealmMapper(final Pattern realmNamePattern, final RealmMapper delegate, final Map<String, String> realmNameMap) {
        super(realmNamePattern, delegate);
        this.realmNameMap = realmNameMap;
    }

    public String getRealmMapping(final String name, final Principal principal, final Evidence evidence) {
        final String mappedRealmPart = super.getRealmMapping(name, principal, evidence);
        if (mappedRealmPart == null) return null;
        return realmNameMap.get(mappedRealmPart);
    }
}
