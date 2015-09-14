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

import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;

import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.password.Password;

/**
 * A {@link CredentialLoader} for loading credentials stored within the 'userPassword' attribute of LDAP entries.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordCredentialLoader implements CredentialLoader {

    static final String DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME = "userPassword";
    static Map<String, CredentialSupport> DEFAULT_CREDENTIAL_SUPPORT = new HashMap<>();

    static {
        DEFAULT_CREDENTIAL_SUPPORT.put("clear", CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put("md5", CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put("sha1", CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put("sha256", CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put("sha384", CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put("sha512", CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put("smd5", CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put("ssha", CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put("ssha256", CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put("ssha384", CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put("ssha512", CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put("crypt_", CredentialSupport.UNKNOWN);
        DEFAULT_CREDENTIAL_SUPPORT.put("crypt", CredentialSupport.UNKNOWN);
    }

    private final String userPasswordAttributeName;

    public UserPasswordCredentialLoader(String userPasswordAttributeName) {
        this.userPasswordAttributeName = userPasswordAttributeName;
    }

    @Override
    public CredentialSupport getCredentialSupport(DirContextFactory contextFactory, String credentialName) {

        String[] credentialNameParts = credentialName.split("-");
        if (credentialNameParts.length < 2 || ! credentialNameParts[0].equals(userPasswordAttributeName)) {
            return CredentialSupport.UNSUPPORTED;
        }

        CredentialSupport response = DEFAULT_CREDENTIAL_SUPPORT.get(credentialNameParts[1]);

        if (response == null) {
            return CredentialSupport.UNSUPPORTED;
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
        public CredentialSupport getCredentialSupport(final String credentialName) {
            Object credential = getCredential(credentialName, Object.class);
            // By this point it is either supported or it isn't - no in-between.
            if (credential != null) {
                return CredentialSupport.FULLY_SUPPORTED;
            }
            return CredentialSupport.UNSUPPORTED;
        }

        @Override
        public <C> C getCredential(String credentialName, Class<C> credentialType) {
            DirContext context = null;
            String[] credentialNameParts = credentialName.split("-");
            if (credentialNameParts.length < 2) {
                if (log.isTraceEnabled()) log.trace("User-password credential name \"" + credentialName + "\" is not in attribute-type form - not supported by LDAP realm");
                return null;
            }
            try {
                context = contextFactory.obtainDirContext(null);

                Attributes attributes = context.getAttributes(distinguishedName, new String[] { credentialNameParts[0] });
                Attribute attribute = attributes.get(credentialNameParts[0]);
                for (int i = 0; i < attribute.size(); i++) {
                    byte[] value = (byte[]) attribute.get(i);

                    Password password = parseUserPassword(value, credentialNameParts[1]);

                    if (credentialType.isInstance(password)) {
                        return credentialType.cast(password);
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
    }

}
