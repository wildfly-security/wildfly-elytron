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

import static org.wildfly.security.auth.provider.ldap.UserPasswordPasswordUtil.parseUserPassword;

import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;

import org.wildfly.security.auth.spi.CredentialSupport;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;

/**
 * A {@link CredentialLoader} for loading credentials stored within the 'userPassword' attribute of LDAP entries.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordCredentialLoader implements CredentialLoader {

    static final String DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME = "userPassword";
    static Map<Class<?>, CredentialSupport> DEFAULT_CREDENTIAL_SUPPORT = new HashMap<>();

    static {
        DEFAULT_CREDENTIAL_SUPPORT.put(ClearPassword.class, CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put(SimpleDigestPassword.class, CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put(SaltedSimpleDigestPassword.class, CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put(BSDUnixDESCryptPassword.class, CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put(UnixDESCryptPassword.class, CredentialSupport.UNKNOWN);
    }

    private final String userPasswordAttributeName;

    public UserPasswordCredentialLoader(String userPasswordAttributeName) {
        this.userPasswordAttributeName = userPasswordAttributeName;
    }

    @Override
    public CredentialSupport getCredentialSupport(DirContextFactory contextFactory, Class<?> credentialType) {
        CredentialSupport response = DEFAULT_CREDENTIAL_SUPPORT.get(credentialType);

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

                    Password password = parseUserPassword(value);

                    if (credentialType.isInstance(password)) {
                        return credentialType.cast(password);
                    }
                }

                return null;
            } catch (NamingException | InvalidKeySpecException e) {
                return null;
            } finally {
                contextFactory.returnContext(context);
            }
        }
    }

}
