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

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.auth.server._private.ElytronMessages.log;

/**
 * A pattern role mapper.
 * <p>
 * Role mapper that maps roles that contain Pattern with replacement. Pattern can capture groups that replacement string can use.
 * Can be used to replace all occurrences of the pattern in role or only the first occurrence.
 *
 * @author <a href="mailto:dvilkola@redhat.com">Diana Vilkolakova</a>
 */
public class RegexRoleMapper implements RoleMapper {

    private Pattern pattern;
    private String replacement;
    private boolean keepNonMapped;
    private boolean replaceAll;

    private RegexRoleMapper(Builder builder) {
        checkNotNullParam("pattern", builder.pattern);
        checkNotNullParam("replacement", builder.replacement);
        if (builder.pattern.length() < 1) {
            throw log.invalidPatternInRegexRoleMapper();
        }
        if (builder.replacement.length() < 1) {
            throw log.invalidReplacementInRegexRoleMapper();
        }
        try {
            this.pattern = Pattern.compile(builder.pattern);
        } catch (PatternSyntaxException ex) {
            throw log.invalidPatternInRegexRoleMapper();
        }
        this.replacement = builder.replacement;
        this.keepNonMapped = builder.keepNonMapped;
        this.replaceAll = builder.replaceAll;
    }

    @Override
    public Roles mapRoles(Roles rolesToMap) {
        return new RegexRoles(rolesToMap, this.pattern, this.replacement, this.keepNonMapped, this.replaceAll);
    }

    /**
     * Construct a new {@link Builder} for creating the {@link RegexRoleMapper}.
     *
     * @return a new {@link Builder} for creating the {@link RegexRoleMapper}.
     */
    public static class Builder {
        private String pattern;
        private String replacement;
        private boolean keepNonMapped = true;
        private boolean replaceAll = false;

        public RegexRoleMapper build() {
            return new RegexRoleMapper(this);
        }

        public RegexRoleMapper.Builder setPattern(String pattern) {
            checkNotNullParam("pattern", pattern);
            this.pattern = pattern;
            return this;
        }

        public RegexRoleMapper.Builder setReplacement(String replacement) {
            checkNotNullParam("replacement", replacement);
            this.replacement = replacement;
            return this;
        }

        public RegexRoleMapper.Builder setKeepNonMapped(boolean keepNonMapped) {
            this.keepNonMapped = keepNonMapped;
            return this;
        }

        /**
         * @param replaceAll if true replaces all occurrences of pattern in role. If false replaces only the first occurrence.
         * @return builder
         */
        public RegexRoleMapper.Builder setReplaceAll(boolean replaceAll) {
            this.replaceAll = replaceAll;
            return this;
        }
    }
}
