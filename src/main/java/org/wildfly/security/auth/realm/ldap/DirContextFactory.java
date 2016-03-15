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

package org.wildfly.security.auth.realm.ldap;

import static org.wildfly.security._private.ElytronMessages.log;

import java.util.EnumSet;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.callback.CallbackHandler;

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
     * @param mode the referral mode for if a referral is encountered querying LDAP; the passed in referral mode can be {@code null}
     *        in which case the default of {@code IGNORE} will be assumed
     * @return a ready to use {@link DirContext} for searching and attribute retrieval
     */
    DirContext obtainDirContext(final ReferralMode mode) throws NamingException;

    /**
     * Obtain a {@link DirContext} based on the credentials extracted from the given {@link CallbackHandler}.
     *
     * @param handler the callback handler used to extract credentials in order to obtain a connected DirContext instance.
     * @param mode the referral mode for if a referral is encountered querying LDAP; the passed in referral mode can be {@code null}
     *        in which case the default of {@code IGNORE} will be assumed
     * @return a ready to use {@link DirContext} for searching and attribute retrieval
     */
    DirContext obtainDirContext(CallbackHandler handler, ReferralMode mode) throws NamingException;

    /**
     * Return the {@link DirContext} once it is no longer required. The returned DirContext is not necessarily an
     * {@link InitialDirContext} and as a result we can not assume it is closeable.
     * Should only be called if a context was successfully obtained.
     *
     * @param context the {@link DirContext} to return
     */
    void returnContext(final DirContext context);

    /**
     * Pass back a {@link DirContext} to this factory to be discarded.
     *
     * The context may be passed back either because it is detected as being invalid or possibly because it has been created to
     * act as a specific account and so should not be pooled.
     *
     * Although the context is being discarded this method allows the factory to perform any additional clean up required around
     * this context.
     *
     * @param context the {@link DirContext} to discard.
     */
    default void discardContext(final DirContext context) {
        if (context instanceof InitialDirContext) {
            try {
                context.close();
                log.debugf("Context [%s] was closed. Connection closed or just returned to the pool.", context);
            } catch (NamingException ignored) {
            }
        }
    };

    // TODO - Obtaining a DirContext after a referral.

    /**
     * The referral mode.
     */
    public enum ReferralMode {
        /**
         * Referrals should be ignored.
         */
        IGNORE("ignore"),
        /**
         * Referrals should be followed.
         */
        FOLLOW("follow"),
        /**
         * Referrals should result in an exception.
         */
        THROW("throw"),
        ;

        private final String value;

        private ReferralMode(final String value) {
            this.value = value;
        }

        /**
         * Get the string value for this referral mode.
         *
         * @return the string value for this referral mode
         */
        public String getValue() {
            return value;
        }

        private static final int fullSize = values().length;

        /**
         * Determine whether the given set is fully populated (or "full"), meaning it contains all possible values.
         *
         * @param set the set
         *
         * @return {@code true} if the set is full, {@code false} otherwise
         */
        public static boolean isFull(final EnumSet<ReferralMode> set) {
            return set != null && set.size() == fullSize;
        }

        /**
         * Determine whether this instance is equal to one of the given instances.
         *
         * @param v1 the first instance
         *
         * @return {@code true} if one of the instances matches this one, {@code false} otherwise
         */
        public boolean in(final ReferralMode v1) {
            return this == v1;
        }

        /**
         * Determine whether this instance is equal to one of the given instances.
         *
         * @param v1 the first instance
         * @param v2 the second instance
         *
         * @return {@code true} if one of the instances matches this one, {@code false} otherwise
         */
        public boolean in(final ReferralMode v1, final ReferralMode v2) {
            return this == v1 || this == v2;
        }

        /**
         * Determine whether this instance is equal to one of the given instances.
         *
         * @param v1 the first instance
         * @param v2 the second instance
         * @param v3 the third instance
         *
         * @return {@code true} if one of the instances matches this one, {@code false} otherwise
         */
        public boolean in(final ReferralMode v1, final ReferralMode v2, final ReferralMode v3) {
            return this == v1 || this == v2 || this == v3;
        }

        /**
         * Determine whether this instance is equal to one of the given instances.
         *
         * @param values the possible values
         *
         * @return {@code true} if one of the instances matches this one, {@code false} otherwise
         */
        public boolean in(final ReferralMode... values) {
            if (values != null) for (ReferralMode value : values) {
                if (this == value) return true;
            }
            return false;
        }
    }
}
