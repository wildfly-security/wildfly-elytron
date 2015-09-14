package org.wildfly.security.auth.provider.ldap;

import org.wildfly.security.auth.server.CredentialSupport;

/**
 * Within LDAP credentials could be stored in different ways, splitting out a CredentialPersister allows different strategies to
 * be plugged into the realm.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public interface CredentialPersister {

    /**
     * Determine whether a given credential is definitely supported, possibly supported (for some identities), or definitely not
     * supported.
     *
     * A DirContextFactory is made available if the directory server is going to be queried but most likely this call will need
     * to be generic as querying a whole directory is not realistic.
     *
     * Note: The DirContextFactory approach will be evolved further for better referral support so it makes it easier for it to
     * be passed in for each call.
     *
     * @param contextFactory The dir context factory to use if a DirContext is required to query the server directly.
     * @param credentialName the credential name
     * @return the level of support for this credential type
     */
    CredentialSupport getCredentialSupport(DirContextFactory contextFactory, String credentialName);

    /**
     * Obtain an {@link IdentityCredentialLoader} to query the credentials for a specific identity.
     *
     * Note: By this point referrals relating to the identity should have been resolved so the {@link DirContextFactory} should
     * be suitable for use with the supplied {@code distinguishedName}
     *
     * @param contextFactory the {@link DirContextFactory} to use to connect to LDAP.
     * @param distinguishedName the distinguished name of the identity.
     * @return An {@link IdentityCredentialLoader} for the specified identity identified by their distinguished name.
     */
    IdentityCredentialPersister forIdentity(DirContextFactory contextFactory, String distinguishedName);

}
