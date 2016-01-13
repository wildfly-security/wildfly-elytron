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

import static org.wildfly.security._private.ElytronMessages.log;

import java.security.Principal;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.evidence.Evidence;

/**
 * A simple regular expression-based realm mapper.  The realm name pattern must contain a single capture group which
 * matches the substring to use as the realm name.  If the substring is not matched, the delegate realm mapper is used.
 * If there is no delegate realm mapper, the default realm is used.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class SimpleRegexRealmMapper implements RealmMapper {
    private final Pattern realmNamePattern;
    private final RealmMapper delegate;

    /**
     * Construct a new instance.
     *
     * @param realmNamePattern the realm name pattern, which must contain at least one capture group (cannot be {@code null})
     * @throws IllegalArgumentException if the given pattern does not contain a capture group
     */
    public SimpleRegexRealmMapper(final Pattern realmNamePattern) {
        this(realmNamePattern, DEFAULT_REALM_MAPPER);
    }

    /**
     * Construct a new instance.
     *
     * @param realmNamePattern the realm name pattern, which must contain at least one capture group (cannot be {@code null})
     * @param delegate the delegate mapper to use if the pattern is not matched (cannot be {@code null})
     * @throws IllegalArgumentException if the given pattern does not contain a capture group
     */
    public SimpleRegexRealmMapper(final Pattern realmNamePattern, final RealmMapper delegate) {
        Assert.checkNotNullParam("realmNamePattern", realmNamePattern);
        Assert.checkNotNullParam("delegate", delegate);
        final int groupCount = realmNamePattern.matcher("").groupCount();
        if (groupCount < 1) {
            throw log.patternRequiresCaptureGroup();
        }
        this.realmNamePattern = realmNamePattern;
        this.delegate = delegate;
    }

    public String getRealmMapping(final String name, final Principal principal, final Evidence evidence) {
        if (name == null) {
            return null;
        }
        final Matcher matcher = realmNamePattern.matcher(name);
        assert matcher.groupCount() >= 1;
        return matcher.matches() ? matcher.group(1) : delegate.getRealmMapping(name, principal, evidence);
    }
}
