/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.credential.source;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

import org.wildfly.common.Assert;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.client.CredentialStoreReference;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;

/**
 * A credential source which is backed by an entry in a credential store.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public final class CredentialStoreCredentialSource implements CredentialSource {
    private final SecurityFactory<CredentialStore> credentialStoreFactory;
    private final CredentialStoreReference credentialStoreReference;
    private volatile CredentialStore credentialStore = null;

    /**
     * Construct a new instance.
     *
     * @param credentialStoreFactory factory to create credential store
     * @param alias alias withing {@link CredentialStore}
     */
    public CredentialStoreCredentialSource(final SecurityFactory<CredentialStore> credentialStoreFactory, final String alias) {
        Assert.checkNotNullParam("credentialStoreFactory", credentialStoreFactory);
        Assert.checkNotNullParam("alias", alias);
        this.credentialStoreFactory = credentialStoreFactory;
        credentialStoreReference = new CredentialStoreReference(null, alias);
    }

    /**
     * Construct a new instance.
     *
     * @param credentialStoreFactory factory to create credential store
     * @param credentialStoreReference {@link CredentialStoreReference} to reference entry in the {@link CredentialStore}
     */
    public CredentialStoreCredentialSource(final SecurityFactory<CredentialStore> credentialStoreFactory, final CredentialStoreReference credentialStoreReference) {
        Assert.checkNotNullParam("credentialStoreFactory", credentialStoreFactory);
        Assert.checkNotNullParam("credentialStoreReference", credentialStoreReference);
        this.credentialStoreFactory = credentialStoreFactory;
        this.credentialStoreReference = credentialStoreReference;
    }

    private void createAndInitCredentialStore() throws IOException {
        try {
            if (credentialStore == null) {
                credentialStore = credentialStoreFactory.create();
            }
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
        try {
            createAndInitCredentialStore();
            Class<? extends Credential> crType = credentialType != null ? credentialType : credentialStoreReference.getType();
            return credentialStore.exists(credentialStoreReference.getAlias(), crType) ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
        } catch (CredentialStoreException e) {
            throw ElytronMessages.log.unableToReadCredential(e);
        } catch (UnsupportedCredentialTypeException e) {
            return SupportLevel.UNSUPPORTED;
        }
    }

    public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
        final C credential;
        final Class<C> crType;
        try {
            createAndInitCredentialStore();
            crType = credentialType != null ? credentialType : (Class<C>) credentialStoreReference.getType();
            credential = credentialStore.retrieve(credentialStoreReference.getAlias(), crType);
        } catch (CredentialStoreException e) {
            throw ElytronMessages.log.unableToReadCredential(e);
        } catch (UnsupportedCredentialTypeException e) {
            return null;
        }
        if (crType.isInstance(credential)
            && (parameterSpec == null || credential.impliesParameters(parameterSpec))
            && (algorithmName == null || credential instanceof AlgorithmCredential && algorithmName.equals(((AlgorithmCredential) credential).getAlgorithm()))) {
            return credential;
        } else {
            return null;
        }
    }
}
