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

import static org.wildfly.security._private.ElytronMessages.*;
import static org.wildfly.security.auth.provider.ldap.UserPasswordPasswordUtil.parseUserPassword;
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
import static org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES;
import static org.wildfly.security.password.interfaces.UnixDESCryptPassword.ALGORITHM_CRYPT_DES;

import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.NoSuchAttributeException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.CredentialSupport;

import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;

import org.wildfly.security.auth.server.RealmUnavailableException;

import org.wildfly.security.password.Password;

/**
 * A {@link CredentialLoader} for loading credentials stored within the 'userPassword' attribute of LDAP entries.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordCredentialLoader implements CredentialLoader, CredentialPersister {

    static final String DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME = "userPassword";
    static Map<String, String> CREDENTIAL_TO_ALGORITHM = new HashMap<>();

    static {
        CREDENTIAL_TO_ALGORITHM.put("clear", ALGORITHM_CLEAR);
        CREDENTIAL_TO_ALGORITHM.put("md5", ALGORITHM_SIMPLE_DIGEST_MD5);
        CREDENTIAL_TO_ALGORITHM.put("sha1", ALGORITHM_SIMPLE_DIGEST_SHA_1);
        CREDENTIAL_TO_ALGORITHM.put("sha256", ALGORITHM_SIMPLE_DIGEST_SHA_256);
        CREDENTIAL_TO_ALGORITHM.put("sha384", ALGORITHM_SIMPLE_DIGEST_SHA_384);
        CREDENTIAL_TO_ALGORITHM.put("sha512", ALGORITHM_SIMPLE_DIGEST_SHA_512);
        CREDENTIAL_TO_ALGORITHM.put("smd5", ALGORITHM_PASSWORD_SALT_DIGEST_MD5);
        CREDENTIAL_TO_ALGORITHM.put("ssha", ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1);
        CREDENTIAL_TO_ALGORITHM.put("ssha256", ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256);
        CREDENTIAL_TO_ALGORITHM.put("ssha384", ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384);
        CREDENTIAL_TO_ALGORITHM.put("ssha512", ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512);
        CREDENTIAL_TO_ALGORITHM.put("crypt_", ALGORITHM_BSD_CRYPT_DES);
        CREDENTIAL_TO_ALGORITHM.put("crypt", ALGORITHM_CRYPT_DES);
    }

    private final String userPasswordAttributeName;

    public UserPasswordCredentialLoader(String userPasswordAttributeName) {
        this.userPasswordAttributeName = userPasswordAttributeName;
    }

    @Override
    public CredentialSupport getCredentialSupport(DirContextFactory contextFactory, String credentialName) {

        int delimiter = credentialName.lastIndexOf('-');
        if (delimiter <= 0) {
            return CredentialSupport.UNSUPPORTED;
        }
        String credentialAttribute = credentialName.substring(0, delimiter);
        String credentialTypeName = credentialName.substring(delimiter + 1);
        if (! credentialAttribute.equals(userPasswordAttributeName)) {
            return CredentialSupport.UNSUPPORTED;
        }

        return CREDENTIAL_TO_ALGORITHM.containsKey(credentialTypeName) ? CredentialSupport.UNKNOWN : CredentialSupport.UNSUPPORTED;
    }

    @Override
    public ForIdentityLoader forIdentity(DirContextFactory contextFactory, String distinguishedName) {
        return new ForIdentityLoader(contextFactory, distinguishedName);
    }

    private class ForIdentityLoader implements IdentityCredentialLoader, IdentityCredentialPersister {

        private final DirContextFactory contextFactory;
        private final String distinguishedName;

        public ForIdentityLoader(DirContextFactory contextFactory, String distinguishedName) {
            this.contextFactory = contextFactory;
            this.distinguishedName = distinguishedName;
        }

        @Override
        public CredentialSupport getCredentialSupport(final String credentialName) {
            Credential credential = getCredential(credentialName, Credential.class);
            // By this point it is either supported or it isn't - no in-between.
            if (credential != null) {
                return CredentialSupport.FULLY_SUPPORTED;
            }
            return CredentialSupport.UNSUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(String credentialName, Class<C> credentialType) {
            DirContext context = null;

            int delimiter = credentialName.lastIndexOf('-');
            if (delimiter <= 0) {
                if (log.isTraceEnabled()) log.trace("User-password credential name \"" + credentialName + "\" is not in attribute-type form - not supported by LDAP realm");
                return null;
            }
            String credentialAttribute = credentialName.substring(0, delimiter);
            String credentialTypeName = credentialName.substring(delimiter + 1);

            try {
                context = contextFactory.obtainDirContext(null);

                Attributes attributes = context.getAttributes(distinguishedName, new String[] { credentialAttribute });
                Attribute attribute = attributes.get(credentialAttribute);
                for (int i = 0; i < attribute.size(); i++) {
                    byte[] value = (byte[]) attribute.get(i);

                    Password password = parseUserPassword(value);

                    String expectedAlgorithm = CREDENTIAL_TO_ALGORITHM.get(credentialTypeName);
                    if (expectedAlgorithm != password.getAlgorithm()) return null;

                    if (credentialType.isAssignableFrom(PasswordCredential.class)) {
                        return credentialType.cast(new PasswordCredential(password));
                    }
                }

            } catch (NamingException | InvalidKeySpecException e) {
                if (log.isTraceEnabled()) log.trace("Getting user-password credential "
                        + credentialType.getName() + " failed. dn=" + distinguishedName, e);
            } finally {
                contextFactory.returnContext(context);
            }
            return null;
        }

        @Override
        public boolean getCredentialPersistSupport(String credentialName) {

            int delimiter = credentialName.lastIndexOf('-');
            if (delimiter <= 0) {
                return false;
            }
            String credentialAttribute = credentialName.substring(0, delimiter);
            String credentialTypeName = credentialName.substring(delimiter + 1);
            if (! credentialAttribute.equals(userPasswordAttributeName)) {
                return false;
            }

            return CREDENTIAL_TO_ALGORITHM.containsKey(credentialTypeName);
        }

        @Override
        public void persistCredential(String credentialName, Credential credential) throws RealmUnavailableException {
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
