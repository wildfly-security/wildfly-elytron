/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.auth.provider.ldap;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

/**
 * Factory for obtaining connected DirContext instances.
 *
 * By using a factory for the contexts different strategies can be substituted in a managed environment.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface DirContextFactory {

    /**
     * Obtain a {@link DirContext} for the configured referral mode.
     *
     * @param mode - The referral mode for if a referral is encountered querying LDAP. The passed in referral mode can be null
     *        in which case the default of IGNORE will be assumed.
     * @return A ready to use {@link DirContext} for searching and attribute retrieval.
     */
    DirContext obtainDirContext(final ReferralMode mode) throws NamingException;

    /**
     * Return the {@link DirContext} once it is no longer required.
     *
     * The returned DirContext is no necessarily an {@link InitialDirContext} as a result we can not assume it is closeable.
     *
     * @param context - The {@link DirContext} to return.
     */
    void returnContext(final DirContext context);

    // TODO - Obtaining a DirContext after a referral.

    // TODO - Is this the correct place to add credential verification?

    public enum ReferralMode {
        IGNORE("ignore"), FOLLOW("follow"), THROW("throw");

        private final String value;

        private ReferralMode(final String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

    }

}
