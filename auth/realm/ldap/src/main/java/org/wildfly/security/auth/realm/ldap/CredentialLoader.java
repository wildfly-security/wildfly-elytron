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

import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;

import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Collection;

/**
 * Within LDAP credentials could be stored in different ways, splitting out a CredentialLoader allows different strategies to be
 * plugged into the realm.
 *
 * This interface allows for general checks to be made on the supported credential types and also enables the realm to obtain an
 * identity specific {@link IdentityCredentialLoader}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
interface CredentialLoader {

    /**
     * Determine whether a given credential is definitely supported, possibly supported (for some identities), or definitely not
     * supported.
     * <p>
     * A DirContextFactory is made available if the directory server is going to be queried but most likely this call will need
     * to be generic as querying a whole directory is not realistic.
     * <p>
     * Note: The DirContextFactory approach will be evolved further for better referral support so it makes it easier for it to
     * be passed in for each call.
     *
     * @param credentialType the credential type (must not be {@code null})
     * @param algorithmName the credential algorithm name
     * @param parameterSpec the algorithm parameters to match, or {@code null} if any parameters are acceptable or the credential type
     *  does not support algorithm parameters
     * @return the level of support for this credential type
     */
    SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException;

    /**
     * Obtain an {@link IdentityCredentialLoader} to query the credentials for a specific identity.
     * <p>
     * Note: By this point referrals relating to the identity should have been resolved so the {@link DirContextFactory} should
     * be suitable for use with the supplied {@code distinguishedName}
     *
     * @param dirContext the {@link DirContext} to use to connect to LDAP.
     * @param distinguishedName the distinguished name of the identity.
     * @param attributes the identity attributes requested by {@link #addRequiredIdentityAttributes(Collection)}
     * @return An {@link IdentityCredentialLoader} for the specified identity identified by their distinguished name.
     */
    IdentityCredentialLoader forIdentity(DirContext dirContext, String distinguishedName, Attributes attributes) throws RealmUnavailableException;

    /**
     * Construct set of LDAP attributes, which should be loaded as part of the identity from identity entry.
     * @param attributes output collection of attributes names, into which should be added
     */
    default void addRequiredIdentityAttributes(Collection<String> attributes) {}

    /**
     * Construct set of LDAP attributes, which should be loaded as binary data.
     * Should be subset of {@link addRequiredIdentityAttributes(Collection)} output.
     * @param attributes output collection of attributes names, into which should be added
     */
    default void addBinaryIdentityAttributes(Collection<String> attributes) {}
}
