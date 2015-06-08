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

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * Simple map-backed security realm.  Uses an in-memory copy-on-write map methodology to map user names to
 * entries.  Since this security realm implementation holds all names in memory, it may not be the best choice
 * for very large security realms.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SimpleMapBackedSecurityRealm implements SecurityRealm {

    private final NameRewriter rewriter;
    private volatile Map<String, SimpleRealmEntry> map = Collections.emptyMap();

    /**
     * Construct a new instance.
     *
     * @param rewriter the name rewriter to use (cannot be {@code null})
     */
    public SimpleMapBackedSecurityRealm(final NameRewriter rewriter) {
        Assert.checkNotNullParam("rewriter", rewriter);
        this.rewriter = rewriter;
    }

    /**
     * Construct a new instance.
     */
    public SimpleMapBackedSecurityRealm() {
        this(NameRewriter.IDENTITY_REWRITER);
    }

    /**
     * Set the realm entry map.  Note that the entry map must <b>not</b> be modified after calling this method.
     * If it needs to be changed, pass in a new map that is a copy of the old map with the required changes.
     *
     * @param map the password map
     */
    public void setPasswordMap(final Map<String, SimpleRealmEntry> map) {
        this.map = map;
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
        name = rewriter.rewriteName(name);
        if (name == null) {
            throw ElytronMessages.log.invalidName();
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

        @Override
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

        @Override
        public boolean verifyCredential(final Object credential) throws RealmUnavailableException {
            try {
                SimpleRealmEntry entry = map.get(name);
                if (entry == null) {
                    return false;
                }

                if (credential instanceof char[]) {
                    final Password password = entry.getPassword();
                    return PasswordFactory.getInstance(password.getAlgorithm()).verify(password, (char[]) credential);
                } else if (credential instanceof ClearPassword) {
                    final Password password = entry.getPassword();
                    return PasswordFactory.getInstance(password.getAlgorithm()).verify(password, ((ClearPassword) credential).getPassword());
                } else {
                    return false;
                }
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RealmUnavailableException(e);
            }
        }

        @Override
        public boolean exists() throws RealmUnavailableException {
            return map.containsKey(name);
        }
    }
}
