package org.wildfly.security.auth.provider.ldap;

import org.wildfly.security.auth.server.RealmUnavailableException;

/**
 * A {@link CredentialPersister} for persisting credentials into LDAP directory.
 *
 * Implementations of this interface are instantiated for a specific identity, as a result all of the methods on this
 * interface are specific to that identity.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public interface IdentityCredentialPersister {

    /**
     * Determine whether a given credential is definitely supported, possibly supported, or definitely not supported.
     *
     * @param credential the credential to check
     * @return {@code true} if persisting of given credential is supported
     */
    boolean getCredentialPersistSupport(Object credential);

    /**
     * Store credential of identity.
     *
     * @param credential the credential
     */
    void persistCredential(Object credential) throws RealmUnavailableException;

    /**
     * Clear all supported credentials of identity.
     */
    void clearCredentials() throws RealmUnavailableException;
}
