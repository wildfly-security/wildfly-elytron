/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

import static org.wildfly.security._private.ElytronMessages.log;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.wildfly.security.auth.util.NameRewriter;
import org.wildfly.security.auth.util.RealmMapper;

/**
 * A security domain.  Security domains encapsulate a set of security policies.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SecurityDomain {
    private final Map<String, SecurityRealm> realmMap;
    private final String defaultRealmName;
    private final NameRewriter[] preRealmRewriters;
    private final RealmMapper realmMapper;
    private final NameRewriter[] postRealmRewriters;

    SecurityDomain(final Map<String, SecurityRealm> realmMap, final String defaultRealmName, final NameRewriter[] preRealmRewriters, final RealmMapper realmMapper, final NameRewriter[] postRealmRewriters) {
        assert realmMap.containsKey(defaultRealmName);
        this.realmMap = realmMap;
        this.defaultRealmName = defaultRealmName;
        this.preRealmRewriters = preRealmRewriters;
        this.realmMapper = realmMapper;
        this.postRealmRewriters = postRealmRewriters;
    }

    /**
     * Create a new security domain builder.
     *
     * @return the builder
     */
    public static Builder builder() {
        return new Builder();
    }

    public ServerAuthenticationContext createNewAuthenticationContext() {
        return new ServerAuthenticationContext(this);
    }

    /**
     * Map the provided name to a {@link RealmIdentity}
     *
     * @param name The name to map.
     * @return The identity for the name.
     */
    public RealmIdentity mapName(String name) {
        for (NameRewriter rewriter : preRealmRewriters) {
            name = rewriter.rewriteName(name);
        }
        String realmName = realmMapper.getRealmMapping(name);
        if (realmName == null) {
            realmName = defaultRealmName;
        }
        SecurityRealm securityRealm = realmMap.get(realmName);
        if (securityRealm == null) {
            securityRealm = realmMap.get(defaultRealmName);
        }
        assert securityRealm != null;
        for (NameRewriter rewriter : postRealmRewriters) {
            name = rewriter.rewriteName(name);
        }
        return securityRealm.createRealmIdentity(name);
    }

    SecurityRealm getRealm(final String realmName) {
        SecurityRealm securityRealm = realmMap.get(realmName);
        if (securityRealm == null) {
            securityRealm = realmMap.get(defaultRealmName);
        }
        return securityRealm;
    }

    CredentialSupport getCredentialSupport(final Class<?> credentialType) {
        CredentialSupport min, max;
        Iterator<SecurityRealm> iterator = realmMap.values().iterator();
        if (iterator.hasNext()) {
            SecurityRealm realm = iterator.next();
            min = max = realm.getCredentialSupport(credentialType);
            while (iterator.hasNext()) {
                realm = iterator.next();
                final CredentialSupport support = realm.getCredentialSupport(credentialType);
                if (support.compareTo(min) < 0) {
                    min = support;
                }
                if (support.compareTo(max) > 0) {
                    max = support;
                }
            }
            if (min == max) return min;
            if (max == CredentialSupport.UNSUPPORTED) {
                return CredentialSupport.UNSUPPORTED;
            } else if (min == CredentialSupport.SUPPORTED) {
                return CredentialSupport.SUPPORTED;
            } else {
                return CredentialSupport.POSSIBLY_SUPPORTED;
            }
        } else {
            return CredentialSupport.UNSUPPORTED;
        }
    }

    CredentialSupport getCredentialSupport(final String realmName, final Class<?> credentialType) {
        final SecurityRealm realm = getRealm(realmName);
        return realm.getCredentialSupport(credentialType);
    }

    public static final class Builder {
        private static final NameRewriter[] NONE = new NameRewriter[0];

        private boolean built = false;

        private final ArrayList<NameRewriter> preRealmRewriters = new ArrayList<>();
        private final ArrayList<NameRewriter> postRealmRewriters = new ArrayList<>();
        private final HashMap<String, SecurityRealm> realms = new HashMap<>();
        private String defaultRealmName;
        private RealmMapper realmMapper = RealmMapper.DEFAULT_REALM_MAPPER;

        public Builder addPreRealmRewriter(NameRewriter rewriter) {
            assertNotBuilt();
            if (rewriter != null) preRealmRewriters.add(rewriter);

            return this;
        }

        public Builder addPostRealmRewriter(NameRewriter rewriter) {
            assertNotBuilt();
            if (rewriter != null) postRealmRewriters.add(rewriter);

            return this;
        }

        public Builder setRealmMapper(RealmMapper realmMapper) {
            assertNotBuilt();
            this.realmMapper = realmMapper == null ? RealmMapper.DEFAULT_REALM_MAPPER : realmMapper;

            return this;
        }

        public Builder addRealm(String name, SecurityRealm realm) {
            assertNotBuilt();
            if (name == null) {
                throw log.nullParameter("name");
            }
            if (realm == null) {
                throw log.nullParameter("realm");
            }
            realms.put(name, realm);

            return this;
        }

        public String getDefaultRealmName() {
            return defaultRealmName;
        }

        public Builder setDefaultRealmName(final String defaultRealmName) {
            assertNotBuilt();
            if (defaultRealmName == null) {
                throw log.nullParameter("defaultRealmName");
            }
            this.defaultRealmName = defaultRealmName;

            return this;
        }

        public SecurityDomain build() {
            final String defaultRealmName = this.defaultRealmName;
            if (defaultRealmName == null) {
                throw log.nullParameter("defaultRealmName");
            }
            final HashMap<String, SecurityRealm> realmMap = new HashMap<>(realms);
            if (! realmMap.containsKey(defaultRealmName)) {
                throw log.realmMapDoesntContainDefault(defaultRealmName);
            }

            assertNotBuilt();
            built = true;

            NameRewriter[] preRealm = preRealmRewriters.isEmpty() ? NONE : preRealmRewriters.toArray(new NameRewriter[preRealmRewriters.size()]);
            NameRewriter[] postRealm = postRealmRewriters.isEmpty() ? NONE : postRealmRewriters.toArray(new NameRewriter[postRealmRewriters.size()]);
            return new SecurityDomain(realmMap, defaultRealmName, preRealm, realmMapper, postRealm);
        }

        private void assertNotBuilt() {
            if (built) {
                throw log.builderAlreadyBuilt();
            }
        }
    }
}
