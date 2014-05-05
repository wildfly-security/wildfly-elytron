/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.security.auth.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A simple regular expression-based realm mapper.  The realm name pattern must contain a single capture group which
 * matches the substring to use as the realm name.  If the substring is not matched, the default realm is used.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class SimpleRegexRealmMapper implements RealmMapper {
    private final Pattern realmNamePattern;

    /**
     * Construct a new instance.
     *
     * @param realmNamePattern the realm name pattern, which must contain at least one capture group
     * @throws IllegalArgumentException if the given pattern does not contain a capture group
     */
    public SimpleRegexRealmMapper(final Pattern realmNamePattern) {
        final int groupCount = realmNamePattern.matcher("").groupCount();
        if (groupCount < 1) {
            throw new IllegalArgumentException("Pattern requires a capture group");
        }
        this.realmNamePattern = realmNamePattern;
    }

    public String getRealmMapping(final String userName) {
        final Matcher matcher = realmNamePattern.matcher(userName);
        assert matcher.groupCount() >= 1;
        return matcher.matches() ? matcher.group(1) : null;
    }
}
