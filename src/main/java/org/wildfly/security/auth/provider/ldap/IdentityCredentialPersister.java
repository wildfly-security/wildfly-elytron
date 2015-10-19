package org.wildfly.security.auth.provider.ldap;

import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.credential.Credential;

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
     * @param credentialName the credential to store
     * @return {@code true} if persisting of given credential is supported
     */
    boolean getCredentialPersistSupport(String credentialName);

    /**
     * Store credential of identity.
     *
     * @param credentialName the credential to store
     * @param credential the credential
     */
    void persistCredential(String credentialName, Credential credential) throws RealmUnavailableException;

    /**
     * Clear all supported credentials of identity.
     */
    void clearCredentials() throws RealmUnavailableException;
}
