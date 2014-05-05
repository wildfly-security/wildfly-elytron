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

package org.wildfly.security.auth.provider;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.wildfly.security.auth.SecurityIdentity;
import org.wildfly.security.auth.login.AuthenticationException;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.util.NameRewriter;
import org.wildfly.security.auth.verifier.Verifier;
import org.wildfly.security.password.Password;

/**
 * Simple map-backed security realm.  Uses an in-memory copy-on-write map methodology to map user names to
 * passwords.  Since this security realm implementation holds all names in memory, it may not be the best choice
 * for very large security realms.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class SimpleMapBackedSecurityRealm implements SecurityRealm {
    private final NameRewriter[] rewriters;
    private volatile Map<NamePrincipal, Password> map = Collections.emptyMap();

    public SimpleMapBackedSecurityRealm(final NameRewriter... rewriters) {
        this.rewriters = rewriters.clone();
    }

    /**
     * Set the password map.  Note that the password map must <b>not</b> be modified after calling this method.
     * If it needs to be changed, pass in a new map that is a copy of the old map with the required changes.
     *
     * @param passwordMap the password map
     */
    public void setPasswordMap(final Map<NamePrincipal, Password> passwordMap) {
        map = passwordMap;
    }

    public Principal mapNameToPrincipal(String name) {
        for (NameRewriter rewriter : rewriters) {
            name = rewriter.rewriteName(name);
        }
        return new NamePrincipal(name);
    }

    public <C> C getCredential(final Class<C> credentialType, final Principal principal) {
        final Password password = map.get(principal);
        return credentialType.isInstance(password) ? credentialType.cast(password) : null;
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

    public CredentialSupport getCredentialSupport(final Class<?> credentialType) {
        return Password.class.isAssignableFrom(credentialType) ? CredentialSupport.POSSIBLY_SUPPORTED : CredentialSupport.UNSUPPORTED;
    }

    public CredentialSupport getCredentialSupport(final Principal principal, final Class<?> credentialType) {
        final Password password = map.get(principal);
        return credentialType.isInstance(password) ? CredentialSupport.SUPPORTED : CredentialSupport.UNSUPPORTED;
    }

    public <P> P proveAuthentic(final Principal principal, final Verifier<P> verifier) throws AuthenticationException {
        final Password password = map.get(principal);
        if (password != null) {
            Class<?> clazz = password.getClass();
            if (! checkType(verifier.getSupportedCredentialTypes(), new HashSet<Class<?>>(), clazz)) {
                throw new AuthenticationException("Unsupported credential type");
            }
            return verifier.performVerification(password);
        } else {
            throw new AuthenticationException("No such user");
        }
    }

    public SecurityIdentity createSecurityIdentity(final Principal principal) {
        return null;
    }
}
