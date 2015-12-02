/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.credential.store.external;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import javax.security.auth.callback.Callback;

import org.wildfly.security.credential.Credential;

/**
 * Base class for credential store API related callbacks. It handles {@link Credential}.
 * It also implements {@link Destroyable} interface.
 *
 * @param <C> credential type
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class ExternalCredentialCallback<C extends Credential> implements Callback, Destroyable {

    private C credential;

    /**
     * Returns credential
     * @return credential
     */
    public C getCredential() {
        return credential;
    }

    /**
     * Sets credential creating.
     * @param credential a credential to set.
     */
    public void setPassword(C credential) {
        this.credential = credential;
    }

    @Override
    public void destroy() throws DestroyFailedException {
        if (credential instanceof Destroyable) {
            ((Destroyable)credential).destroy();
            credential = null;
        }
    }

    @Override
    public boolean isDestroyed() {
        return (credential == null);
    }
}
