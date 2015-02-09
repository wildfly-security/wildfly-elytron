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

import static org.wildfly.security.auth.provider.ldap.UserPasswordPasswordUtil.UTF_8;
import static org.wildfly.security.auth.provider.ldap.UserPasswordPasswordUtil.parseUserPassword;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import static org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;

import org.wildfly.security.auth.provider.CredentialSupport;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.BSDUnixDESCryptPasswordSpec;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.spec.SimpleDigestPasswordSpec;
import org.wildfly.security.password.spec.SaltedSimpleDigestPasswordSpec;

/**
 * A {@link CredentialLoader} for loading credentials stored within the 'userPassword' attribute of LDAP entries.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordCredentialLoader implements CredentialLoader {

    static final String DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME = "userPassword";

    private final String userPasswordAttributeName;
    private final Map<Class<?>, CredentialSupport> credentialSupportMap;

    public UserPasswordCredentialLoader(String userPasswordAttributeName, Map<Class<?>, CredentialSupport> credentialSupportMap) {
        this.userPasswordAttributeName = userPasswordAttributeName;
        this.credentialSupportMap = credentialSupportMap;
    }

    @Override
    public CredentialSupport getCredentialSupport(DirContextFactory contextFactory, Class<?> credentialType) {
        if (credentialSupportMap.isEmpty()) {
            return CredentialSupport.UNKNOWN;
        }
        CredentialSupport response = credentialSupportMap.get(credentialType);
        if (response == null) {
            response = CredentialSupport.UNSUPPORTED;
        }

        return response;
    }

    @Override
    public IdentityCredentialLoader forIdentity(DirContextFactory contextFactory, String distinguishedName) {
        return new ForIdentityLoader(contextFactory, distinguishedName);
    }

    private class ForIdentityLoader implements IdentityCredentialLoader {

        private final DirContextFactory contextFactory;
        private final String distinguishedName;

        public ForIdentityLoader(DirContextFactory contextFactory, String distinguishedName) {
            this.contextFactory = contextFactory;
            this.distinguishedName = distinguishedName;
        }

        @Override
        public CredentialSupport getCredentialSupport(Class<?> credentialType) {
            Object credential = getCredential(credentialType);
            // By this point it is either supported or it isn't - no in-between.
            if (credential != null && credentialType.isInstance(credential)) {
                return CredentialSupport.FULLY_SUPPORTED;
            }

            return CredentialSupport.UNSUPPORTED;
        }

        @Override
        public <C> C getCredential(Class<C> credentialType) {
            DirContext context = null;
            try {
                context = contextFactory.obtainDirContext(null);

                Attributes attributes = context.getAttributes(distinguishedName, new String[] { userPasswordAttributeName });
                Attribute attribute = attributes.get(userPasswordAttributeName);
                for (int i = 0; i < attribute.size(); i++) {
                    byte[] value = (byte[]) attribute.get(i);

                    PasswordSpec spec = parseUserPassword(value);
                    PasswordFactory pf = PasswordFactory.getInstance(toAlgorithm(spec));

                    Password password = pf.generatePassword(spec);

                    if (credentialType.isInstance(password)) {
                        return credentialType.cast(password);
                    }

                    System.out.println(new String(value, UTF_8));
                }

                return null;
            } catch (NamingException | InvalidKeySpecException | NoSuchAlgorithmException e) {
                return null;
            } finally {
                contextFactory.returnContext(context);
            }
        }

        private String toAlgorithm(PasswordSpec passwordSpec) {
            if (passwordSpec instanceof ClearPasswordSpec) {
                return ALGORITHM_CLEAR;
            } else if (passwordSpec instanceof SimpleDigestPasswordSpec) {
                return ((SimpleDigestPasswordSpec) passwordSpec).getAlgorithm();
            } else if (passwordSpec instanceof SaltedSimpleDigestPasswordSpec) {
                return ((SaltedSimpleDigestPasswordSpec) passwordSpec).getAlgorithm();
            } else if (passwordSpec instanceof BSDUnixDESCryptPasswordSpec) {
                return ALGORITHM_BSD_CRYPT_DES;
            }

            return null;
        }
    }

}
