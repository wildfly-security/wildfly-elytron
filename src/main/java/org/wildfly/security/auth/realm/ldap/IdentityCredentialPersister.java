package org.wildfly.security.auth.realm.ldap;

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
public interface IdentityCredentialPersister extends IdentityCredentialLoader {

    /**
     * Determine whether a given credential type can be persisted by this credential persister.
     *
     * @param credentialType the credential type (must not be {@code null})
     * @param algorithmName the credential algorithm name, if any
     * @return {@code true} if persisting of given credential is supported
     */
    boolean getCredentialPersistSupport(Class<? extends Credential> credentialType, String algorithmName);

    /**
     * Store credential of identity.
     *
     * @param credential the credential
     */
    void persistCredential(Credential credential) throws RealmUnavailableException;

    /**
     * Clear all supported credentials of identity.
     */
    void clearCredentials() throws RealmUnavailableException;
}
