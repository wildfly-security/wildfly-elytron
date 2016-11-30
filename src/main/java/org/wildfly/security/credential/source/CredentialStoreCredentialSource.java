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
import java.security.spec.AlgorithmParameterSpec;

import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.common.Assert;
import org.wildfly.common.function.ExceptionSupplier;
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
    private final ExceptionSupplier<CredentialStore, ConfigXMLParseException> credentialStoreFactory;
    private final CredentialStoreReference credentialStoreReference;
    private volatile CredentialStore credentialStore = null;

    /**
     * Construct a new instance.
     *
     * @param credentialStoreFactory factory to create credential store
     * @param credentialStoreReference {@link CredentialStoreReference} to reference entry in the {@link CredentialStore}
     */
    public CredentialStoreCredentialSource(final ExceptionSupplier<CredentialStore, ConfigXMLParseException> credentialStoreFactory, final CredentialStoreReference credentialStoreReference) {
        Assert.checkNotNullParam("credentialStoreFactory", credentialStoreFactory);
        Assert.checkNotNullParam("credentialStoreReference", credentialStoreReference);
        this.credentialStoreFactory = credentialStoreFactory;
        this.credentialStoreReference = credentialStoreReference;
    }

    private void createAndInitCredentialStore() throws ConfigXMLParseException {
        if (credentialStore == null) {
            credentialStore = credentialStoreFactory.get();
        }
    }

    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
        Assert.checkNotNullParam("credentialType", credentialType);
        try {
            createAndInitCredentialStore();
            return credentialStore.exists(credentialStoreReference.getAlias(), credentialType) ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
        } catch (CredentialStoreException | ConfigXMLParseException e) {
            throw ElytronMessages.log.unableToReadCredential(e);
        } catch (UnsupportedCredentialTypeException e) {
            return SupportLevel.UNSUPPORTED;
        }
    }

    public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
        Assert.checkNotNullParam("credentialType", credentialType);
        final C credential;
        try {
            createAndInitCredentialStore();
            credential = credentialStore.retrieve(credentialStoreReference.getAlias(), credentialType);
        } catch (CredentialStoreException | ConfigXMLParseException e) {
            throw ElytronMessages.log.unableToReadCredential(e);
        } catch (UnsupportedCredentialTypeException e) {
            return null;
        }
        if (credentialType.isInstance(credential)
            && (parameterSpec == null || credential.impliesParameters(parameterSpec))
            && (algorithmName == null || credential instanceof AlgorithmCredential && algorithmName.equals(((AlgorithmCredential) credential).getAlgorithm()))) {
            return credential;
        } else {
            return null;
        }
    }
}
