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
import static org.wildfly.security.auth.realm.ldap.UserPasswordPasswordUtil.parseUserPassword;

import java.io.IOException;
import java.security.spec.InvalidKeySpecException;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.NoSuchAttributeException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.password.Password;

/**
 * A {@link CredentialLoader} for loading credentials stored within the 'userPassword' attribute of LDAP entries.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordCredentialLoader implements CredentialPersister {

    static final String DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME = "userPassword";

    private final String userPasswordAttributeName;

    /**
     * Construct a new {@link UserPasswordCredentialLoader} for a specific attribute name.
     *
     * @param userPasswordAttributeName the name of the attribute within the LDAP entry that holds the credential.
     */
    UserPasswordCredentialLoader(final String userPasswordAttributeName) {
        Assert.checkNotNullParam("userPasswordAttributeName", userPasswordAttributeName);
        this.userPasswordAttributeName = userPasswordAttributeName;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final DirContextFactory contextFactory, final Class<? extends Credential> credentialType, final String credentialAlgorithm) throws RealmUnavailableException {
        if (credentialType == PasswordCredential.class) {
            if (credentialAlgorithm == null) return SupportLevel.SUPPORTED;
            if (UserPasswordPasswordUtil.isAlgorithmSupported(credentialAlgorithm)) return SupportLevel.POSSIBLY_SUPPORTED;
        }
        return SupportLevel.UNSUPPORTED;
    }

    @Override
    public IdentityCredentialPersister forIdentity(DirContextFactory contextFactory, String distinguishedName) {
        return new ForIdentityLoader(contextFactory, distinguishedName);
    }

    EvidenceVerifier toEvidenceVerifier() {
        return new EvidenceVerifier() {

            @Override
            public SupportLevel getEvidenceVerifySupport(final DirContextFactory contextFactory, final Class<? extends Evidence> evidenceType, final String evidenceAlgorithm) throws RealmUnavailableException {
                // If we can acquire PasswordCredential and it support provided evidence, we can verify.
                if ( ! PasswordCredential.canVerifyEvidence(evidenceType, evidenceAlgorithm)) return SupportLevel.UNSUPPORTED;
                return getCredentialAcquireSupport(contextFactory, PasswordCredential.class, evidenceAlgorithm);
            }

            @Override
            public IdentityEvidenceVerifier forIdentity(DirContextFactory contextFactory, String distinguishedName) throws RealmUnavailableException {
                return new ForIdentityLoader(contextFactory, distinguishedName);
            }
        };
    }

    private class ForIdentityLoader implements IdentityCredentialPersister, IdentityEvidenceVerifier {

        private final DirContextFactory contextFactory;
        private final String distinguishedName;

        public ForIdentityLoader(DirContextFactory contextFactory, String distinguishedName) {
            this.contextFactory = contextFactory;
            this.distinguishedName = distinguishedName;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String credentialAlgorithm) {
            Credential credential = getCredential(credentialType, credentialAlgorithm);
            // By this point it is either supported or it isn't - no in-between.
            if (credential != null) {
                return SupportLevel.SUPPORTED;
            }
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String evidenceAlgorithm) throws RealmUnavailableException {
            // If we can acquire PasswordCredential and it support provided evidence, we can verify.
            if ( ! PasswordCredential.canVerifyEvidence(evidenceType, evidenceAlgorithm)) return SupportLevel.UNSUPPORTED;
            return getCredentialAcquireSupport(PasswordCredential.class, null);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String credentialAlgorithm) {
            if (credentialType != PasswordCredential.class) {
                return null;
            }

            DirContext context;
            try {
                context = contextFactory.obtainDirContext(null);
            } catch (NamingException e) {
                if (log.isTraceEnabled()) {
                    log.trace("Getting user-password credential " + credentialType.getName() + " failed. dn=" + distinguishedName, e);
                }
                return null;
            }
            try {
                Attributes attributes = context.getAttributes(distinguishedName, new String[] { userPasswordAttributeName });
                Attribute attribute = attributes.get(userPasswordAttributeName);
                final int size = attribute.size();
                for (int i = 0; i < size; i++) {
                    byte[] value = (byte[]) attribute.get(i);

                    Password password = parseUserPassword(value);

                    if (credentialType.isAssignableFrom(PasswordCredential.class) && (credentialAlgorithm == null || credentialAlgorithm.equals(password.getAlgorithm()))) {
                        return credentialType.cast(new PasswordCredential(password));
                    }
                }

            } catch (NamingException | InvalidKeySpecException e) {
                if (log.isTraceEnabled()) {
                    log.trace("Getting user-password credential " + credentialType.getName() + " failed. dn=" + distinguishedName, e);
                }
            } finally {
                contextFactory.returnContext(context);
            }
            return null;
        }

        @Override
        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            final PasswordCredential credential = getCredential(PasswordCredential.class, null);
            if (credential == null) return false;
            return credential.verify(evidence);
        }

        @Override
        public boolean getCredentialPersistSupport(final Class<? extends Credential> credentialType, final String credentialAlgorithm) {
            return credentialType == PasswordCredential.class && (credentialAlgorithm == null || UserPasswordPasswordUtil.isAlgorithmSupported(credentialAlgorithm));
        }

        @Override
        public void persistCredential(final Credential credential) throws RealmUnavailableException {
            // TODO - We probably need some better resolution here of the existing attributes - i.e. different types we would want to add, same type we would want to replace.

            DirContext context;
            try {
                context = contextFactory.obtainDirContext(null);
            } catch (NamingException e) {
                throw log.ldapRealmCredentialPersistingFailed(credential.toString(), distinguishedName, e);
            }
            try {
                byte[] composedPassword = UserPasswordPasswordUtil.composeUserPassword(credential.castAndApply(PasswordCredential.class, PasswordCredential::getPassword));
                Assert.assertNotNull(composedPassword);

                Attributes attributes = new BasicAttributes();
                attributes.put(userPasswordAttributeName, composedPassword);

                context.modifyAttributes(distinguishedName, DirContext.ADD_ATTRIBUTE, attributes);

            } catch (NamingException | IOException e) {
                throw log.ldapRealmCredentialPersistingFailed(credential.toString(), distinguishedName, e);
            } finally {
                contextFactory.returnContext(context);
            }
        }

        @Override
        public void clearCredentials() throws RealmUnavailableException {
            DirContext context;
            try {
                context = contextFactory.obtainDirContext(null);
            } catch (NamingException e) {
                throw log.ldapRealmCredentialClearingFailed(distinguishedName, e);
            }
            try {
                Attributes attributes = new BasicAttributes();
                attributes.put(new BasicAttribute(userPasswordAttributeName));

                context.modifyAttributes(distinguishedName, DirContext.REMOVE_ATTRIBUTE, attributes);
            } catch (NoSuchAttributeException e) {
                // ignore if already clear
            } catch (NamingException e) {
                throw log.ldapRealmCredentialClearingFailed(distinguishedName, e);
            } finally {
                contextFactory.returnContext(context);
            }
        }
    }

}
