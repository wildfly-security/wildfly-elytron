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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.wildfly.security.auth.spi.Attributes;
import org.wildfly.security.auth.spi.AuthorizationIdentity;
import org.wildfly.security.auth.spi.CredentialSupport;
import org.wildfly.security.auth.spi.RealmIdentity;
import org.wildfly.security.auth.spi.RealmUnavailableException;
import org.wildfly.security.auth.spi.SecurityRealm;
import org.wildfly.security.auth.util.NameRewriter;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;

/**
 * Simple map-backed security realm.  Uses an in-memory copy-on-write map methodology to map user names to
 * entries.  Since this security realm implementation holds all names in memory, it may not be the best choice
 * for very large security realms.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SimpleMapBackedSecurityRealm implements SecurityRealm {

    private final NameRewriter[] rewriters;
    private volatile Map<String, SimpleRealmEntry> map = Collections.emptyMap();

    /**
     * Construct a new instance.
     *
     * @param rewriters the name rewriters to use
     */
    public SimpleMapBackedSecurityRealm(final NameRewriter... rewriters) {
        this.rewriters = rewriters.clone();
    }

    /**
     * Set the realm entry map.  Note that the entry map must <b>not</b> be modified after calling this method.
     * If it needs to be changed, pass in a new map that is a copy of the old map with the required changes.
     *
     * @param passwordMap the password map
     */
    public void setPasswordMap(final Map<String, SimpleRealmEntry> passwordMap) {
        map = passwordMap;
    }

    /**
     * Set the password map to contain a single entry.
     *
     * @param name the entry name
     * @param password the password
     * @param attributes the identity attributes
     */
    public void setPasswordMap(final String name, final Password password, final Attributes attributes) {
        map = Collections.singletonMap(name, new SimpleRealmEntry(password, attributes));
    }

    /**
     * Set the password map to contain a single entry.
     *
     * @param name the entry name
     * @param password the password
     */
    public void setPasswordMap(final String name, final Password password) {
        map = Collections.singletonMap(name, new SimpleRealmEntry(password));
    }

    @Override
    public RealmIdentity createRealmIdentity(String name) {
        for (NameRewriter rewriter : rewriters) {
            name = rewriter.rewriteName(name);
        }
        return new SimpleMapRealmIdentity(name);
    }

    private boolean checkType(final Set<Class<?>> supportedTypes, HashSet<Class<?>> checked, Class<?> actualType) {
        return actualType != null && checked.add(actualType) && (supportedTypes.contains(actualType) || checkType(supportedTypes, checked, actualType.getSuperclass()) || checkInterfaces(supportedTypes, checked, actualType));
    }

    private boolean checkInterfaces(final Set<Class<?>> supportedTypes, HashSet<Class<?>> checked, final Class<?> actualType) {
        for (Class<?> clazz : actualType.getInterfaces()) {
            if (checkType(supportedTypes, checked, clazz)) return true;
        }
        return false;
    }

    @Override
    public CredentialSupport getCredentialSupport(final Class<?> credentialType) {
        return Password.class.isAssignableFrom(credentialType) ? CredentialSupport.UNKNOWN : CredentialSupport.UNSUPPORTED;
    }

    private class SimpleMapRealmIdentity implements RealmIdentity {

        private final String name;

        SimpleMapRealmIdentity(final String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        @Override
        public CredentialSupport getCredentialSupport(Class<?> credentialType) {
            final SimpleRealmEntry entry = map.get(name);
            if (entry == null) return CredentialSupport.UNSUPPORTED;
            final Password password = entry.getPassword();
            return credentialType.isInstance(password) ? CredentialSupport.FULLY_SUPPORTED : CredentialSupport.UNSUPPORTED;
        }

        @Override
        public <C> C getCredential(Class<C> credentialType) {
            final SimpleRealmEntry entry = map.get(name);
            if (entry == null) return null;
            final Password password = entry.getPassword();
            return credentialType.isInstance(password) ? credentialType.cast(password) : null;
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() {
            final SimpleRealmEntry entry = map.get(name);
            return entry == null ? AuthorizationIdentity.EMPTY : AuthorizationIdentity.basicIdentity(entry.getAttributes());
        }

        public boolean verifyCredential(final Object credential) throws RealmUnavailableException {
            if (credential instanceof char[]) try {
                final SimpleRealmEntry entry = map.get(name);
                if (entry == null) {
                    return false;
                }
                final Password password = entry.getPassword();
                return PasswordFactory.getInstance(password.getAlgorithm()).verify(password, (char[]) credential);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RealmUnavailableException(e);
            } else {
                return false;
            }
        }

        public boolean exists() throws RealmUnavailableException {
            return map.containsKey(name);
        }
    }
}
