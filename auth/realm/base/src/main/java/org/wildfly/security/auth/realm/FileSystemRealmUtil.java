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

import java.nio.charset.Charset;
import java.nio.file.Path;
import java.util.List;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm.Identity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.password.spec.Encoding;

/**
 * A utility class to utilize methods from the {@code FileSystemSecurityRealm} class for the Elytron Tool.
 *
 * @author <a href="mailto:araskar@redhat.com">Ashpan Raskar</a>
 */
public class FileSystemRealmUtil {
    Identity identity;
    public FileSystemRealmUtil(String name, Path path, IdentitySharedExclusiveLock.IdentityLock lock, Charset hashCharset, Encoding hashEncoding){
        this.identity = new Identity(name, path, lock, hashCharset, hashEncoding, null);
    }

    public LoadedIdentity loadIdentity(boolean skipCredentials, boolean skipAttributes) throws RealmUnavailableException{
        FileSystemSecurityRealm.LoadedIdentity fakeIdentity = this.identity.loadIdentityPrivileged(false, false);
        return(new LoadedIdentity(fakeIdentity.getName(), fakeIdentity.getCredentials(), fakeIdentity.getAttributes(), fakeIdentity.getHashEncoding()));
    }

    public static class LoadedIdentity {
        FileSystemSecurityRealm.LoadedIdentity loadedIdentity = null;
        LoadedIdentity(final String name, final List<Credential> credentials, final Attributes attributes, final Encoding hashEncoding) {
            this.loadedIdentity = new FileSystemSecurityRealm.LoadedIdentity(name, credentials, attributes, hashEncoding);
        }
        public String getName() {
            return this.loadedIdentity.getName();
        }
        public Attributes getAttributes() {
            return this.loadedIdentity.getAttributes();
        }
        public List<Credential> getCredentials() {
            return this.loadedIdentity.getCredentials();
        }
        Encoding getHashEncoding() {
            return this.loadedIdentity.getHashEncoding();
        }
    }
}
