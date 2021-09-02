/*
 * JBoss, Home of Professional Open Source
 * Copyright 2021 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.realm;


import java.util.List;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableRealmIdentityIterator;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.credential.Credential;

/**
 * A utility class to utilize methods from the {@code FileSystemSecurityRealm} class for the Elytron Tool.
 *
 * @author <a href="mailto:araskar@redhat.com">Ashpan Raskar</a>
 */
public class FileSystemRealmUtil {

    /**
     * Converts a pre-existing unencrypted {@code FileSystemSecurityRealm} to a newly created encrypted {@code FileSystemSecurityRealm}
     *
     * @param unencryptedRealm the {@code FileSystemSecurityRealm} without any encryption applied
     * @param encryptedRealm the {@code FileSystemSecurityRealm} configured with a SecretKey to encrypt identity data
     * @throws RealmUnavailableException if either realm is unavailable
     */
    public static void createEncryptedRealmFromUnencrypted(FileSystemSecurityRealm unencryptedRealm, FileSystemSecurityRealm encryptedRealm) throws RealmUnavailableException {
        Assert.checkNotNullParam("unencryptedRealm", unencryptedRealm);
        Assert.checkNotNullParam("encryptedRealm", encryptedRealm);

        ModifiableRealmIdentityIterator realmIterator = unencryptedRealm.getRealmIdentityIterator();

        while (realmIterator.hasNext()) {
            ModifiableRealmIdentity identity = realmIterator.next();
            List<Credential> credentials = ((FileSystemSecurityRealm.Identity) identity).loadCredentials();
            Attributes attributes = identity.getAttributes();

            ModifiableRealmIdentity newIdentity = encryptedRealm.getRealmIdentityForUpdate(new NamePrincipal(identity.getRealmIdentityPrincipal().getName()));
            newIdentity.create();
            newIdentity.setCredentials(credentials);
            newIdentity.setAttributes(attributes);
            newIdentity.dispose();
        }
        realmIterator.close();
    }

}
