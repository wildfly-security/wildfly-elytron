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
package org.wildfly.security.authz;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.StreamSupport;

import static org.wildfly.security.auth.server._private.ElytronMessages.log;

/**
 * A regex roles.
 * <p>
 * Roles that are checked against pattern. Roles that contain the pattern are then replaced using the replacement. Pattern can capture groups that replacement can make use of.
 * It is possible to replace all occurrences or only the first occurrence of the pattern in role.
 *
 * @author <a href="mailto:dvilkola@redhat.com">Diana Vilkolakova</a>
 */
class RegexRoles implements Roles {
    private final Roles delegate;
    private final Pattern pattern;
    private final String replace;
    private final boolean keepNonMapped;
    private final boolean replaceAll;

    RegexRoles(final Roles delegate, Pattern pattern, final String replace, final boolean keepNonMapped, final boolean replaceAll) {
        this.delegate = delegate;
        this.pattern = pattern;
        this.replace = replace;
        this.keepNonMapped = keepNonMapped;
        this.replaceAll = replaceAll;
    }

    public boolean contains(final String roleName) {
        try {
            return StreamSupport.stream(delegate.spliterator(), false).anyMatch(role ->
            {
                String pattern = this.pattern.pattern();
                boolean containsRegex = this.pattern.matcher(role).find();
                boolean containsRegexAndRoleExists = containsRegex &&
                        (replaceAll ? role.replaceAll(pattern, replace).equals(roleName) : role.replaceFirst(pattern, replace).equals(roleName));
                boolean doesNotContainRegexButRoleExists = !containsRegex && keepNonMapped && role.equals(roleName);
                return containsRegexAndRoleExists || doesNotContainRegexButRoleExists;
            });
        } catch (PatternSyntaxException | IndexOutOfBoundsException ex) {
            throw log.invalidReplacementInRegexRoleMapper();
        }
    }

    @Override
    public Iterator<String> iterator() {
        final Iterator<String> iterator = delegate.iterator();

        return new Iterator<String>() {
            String next = null;

            @Override
            public boolean hasNext() {
                if (next != null) return true;

                while (iterator.hasNext()) {
                    String nextt = iterator.next();
                    if (pattern.matcher(nextt).find()) {
                        next = replaceAll ? nextt.replaceAll(pattern.pattern(), replace) : nextt.replaceFirst(pattern.pattern(), replace);
                        return true;
                    } else if (keepNonMapped) {
                        next = nextt;
                        return true;
                    }
                }
                return false;
            }

            @Override
            public String next() {
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                final String next = this.next;
                this.next = null;
                return next;
            }
        };
    }
}
