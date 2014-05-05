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

import java.util.Map;
import java.util.regex.Pattern;

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
     * @param realmNamePattern the realm portion pattern
     * @param realmNameMap the realm portion to realm name map
     */
    public MappedRegexRealmMapper(final Pattern realmNamePattern, final Map<String, String> realmNameMap) {
        super(realmNamePattern);
        this.realmNameMap = realmNameMap;
    }

    public String getRealmMapping(final String userName) {
        final String mappedRealmPart = super.getRealmMapping(userName);
        if (mappedRealmPart == null) return null;
        return realmNameMap.get(mappedRealmPart);
    }
}
