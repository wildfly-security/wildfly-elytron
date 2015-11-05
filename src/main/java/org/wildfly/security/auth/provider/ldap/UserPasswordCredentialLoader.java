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

package org.wildfly.security.auth.provider.ldap;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.auth.provider.ldap.UserPasswordPasswordUtil.parseUserPassword;
import static org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_1;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.UnixDESCryptPassword.ALGORITHM_CRYPT_DES;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;

/**
 * A {@link CredentialLoader} for loading credentials stored within the 'userPassword' attribute of LDAP entries.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordCredentialLoader implements CredentialPersister {

    static final String DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME = "userPassword";

    public static final Set<String> SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(
        new HashSet<>(
            Arrays.asList(ALGORITHM_CLEAR, ALGORITHM_SIMPLE_DIGEST_MD5, ALGORITHM_SIMPLE_DIGEST_SHA_1,
                ALGORITHM_SIMPLE_DIGEST_SHA_256, ALGORITHM_SIMPLE_DIGEST_SHA_384, ALGORITHM_SIMPLE_DIGEST_SHA_512,
                ALGORITHM_PASSWORD_SALT_DIGEST_MD5, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256,
                ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, ALGORITHM_BSD_CRYPT_DES, ALGORITHM_CRYPT_DES)
            )
        );

    private final String userPasswordAttributeName;

    // TODO - withCertaintly could be stores with the values in the map so some credential names are always supported and some only possible.
    // Also control of which credentials can be persisted could have similar treatment.

    private final boolean withCertainty;
    private final Map<String, Set<String>> credentialNameAlgorithms;

    UserPasswordCredentialLoader(final boolean withCertainty, final Map<String, Set<String>> credentialNameAlgorithms) {
        this(DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME, withCertainty, credentialNameAlgorithms);
    }

    /**
     * Construct a new {@link UserPasswordCredentialLoader} for a specific attribute name.
     *
     * @param userPasswordAttributeName the name of the attribute within the LDAP entry that holds the credential.
     * @param withCertainty are the named credentials certainly supported for all identities or will it vary identity by identity.
     * @param credentialNameAlgorithms the {@link Map} of supported credential names mapped to the corresponding algorithms.  The Map that is passed in must not be modified further.
     */
    UserPasswordCredentialLoader(final String userPasswordAttributeName, final boolean withCertainty, final Map<String, Set<String>> credentialNameAlgorithms) {
        this.userPasswordAttributeName = userPasswordAttributeName;
        this.withCertainty = withCertainty;
        this.credentialNameAlgorithms = credentialNameAlgorithms;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(DirContextFactory contextFactory, String credentialName) {
        return credentialNameAlgorithms.containsKey(credentialName) ? withCertainty ? SupportLevel.SUPPORTED : SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public IdentityCredentialPersister forIdentity(DirContextFactory contextFactory, String distinguishedName) {
        return new ForIdentityLoader(contextFactory, distinguishedName);
    }

    EvidenceVerifier toEvidenceVerifier() {
        return new EvidenceVerifier() {

            @Override
            public SupportLevel getEvidenceVerifySupport(DirContextFactory contextFactory, String credentialName) throws RealmUnavailableException {
                // If it is obtainable, it is verifiable.
                return getCredentialAcquireSupport(contextFactory, credentialName);
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
        public SupportLevel getCredentialAcquireSupport(final String credentialName) {
            Credential credential = getCredential(credentialName, Credential.class);
            // By this point it is either supported or it isn't - no in-between.
            if (credential != null) {
                return SupportLevel.SUPPORTED;
            }
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public SupportLevel getEvidenceVeridySupport(String credentialName) {
         // If it is obtainable, it is verifiable.
            return getCredentialAcquireSupport(credentialName);
        }

        @Override
        public <C extends Credential> C getCredential(String credentialName, Class<C> credentialType) {
            DirContext context = null;

            Set<String> acceptedAlgorithms = credentialNameAlgorithms.get(credentialName);
            if (acceptedAlgorithms == null) {
                return null;
            }

            try {
                context = contextFactory.obtainDirContext(null);

                Attributes attributes = context.getAttributes(distinguishedName, new String[] { userPasswordAttributeName });
                Attribute attribute = attributes.get(userPasswordAttributeName);
                for (int i = 0; i < attribute.size(); i++) {
                    byte[] value = (byte[]) attribute.get(i);

                    Password password = parseUserPassword(value);
                    if (acceptedAlgorithms.isEmpty() == false && acceptedAlgorithms.contains(password.getAlgorithm()) == false) {
                        return null;
                    }

                    if (credentialType.isAssignableFrom(PasswordCredential.class)) {
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
        public boolean verifyEvidence(DirContextFactory contextFactory, String credentialName, Evidence evidence) throws RealmUnavailableException {
            if (evidence instanceof PasswordGuessEvidence) {
                final PasswordCredential credential = getCredential(credentialName, PasswordCredential.class);
                if (credential != null) try {
                    char[] guess = ((PasswordGuessEvidence) evidence).getGuess();
                    final Password password = credential.getPassword();
                    final PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm());
                    final Password translated = passwordFactory.translate(password);
                    return passwordFactory.verify(translated, guess);
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    return false;
                }
            }

            return false;
        }

        @Override
        public boolean getCredentialPersistSupport(String credentialName) {
            return credentialNameAlgorithms.containsKey(credentialName);
        }

        @Override
        public void persistCredential(String credentialName, Credential credential) throws RealmUnavailableException {
            // TODO - We probably need some better resolution here of the existing attributes - i.e. different types we would want to add, same type we would want to replace.

            DirContext context = null;
            try {
                context = contextFactory.obtainDirContext(null);

                byte[] composedPassword = UserPasswordPasswordUtil.composeUserPassword((Password) credential);
                Assert.assertNotNull(composedPassword);

                Attributes attributes = new BasicAttributes();
                attributes.put(userPasswordAttributeName, composedPassword);

                context.modifyAttributes(distinguishedName, DirContext.ADD_ATTRIBUTE, attributes);

            } catch (NamingException | IOException e) {
                throw log.ldapRealmCredentialPersistingFailed(credential.toString(), credentialName, distinguishedName, e);
            } finally {
                contextFactory.returnContext(context);
            }
        }

        @Override
        public void clearCredentials() throws RealmUnavailableException {
            DirContext context = null;
            try {
                context = contextFactory.obtainDirContext(null);

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
