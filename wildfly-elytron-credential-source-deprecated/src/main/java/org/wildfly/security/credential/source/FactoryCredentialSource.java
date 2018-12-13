/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import org.wildfly.common.Assert;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * A credential source which is backed by a credential security factory.
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
@Deprecated
public class FactoryCredentialSource implements CredentialSource {
    private SecurityFactory<? extends Credential> credentialFactory;

    /**
     * Construct a new instance.
     *
     * @param credentialFactory the entry factory to use to instantiate the entry (must not be {@code null})
     */
    public FactoryCredentialSource(SecurityFactory<? extends Credential> credentialFactory) {
        Assert.checkNotNullParam("credentialFactory", credentialFactory);
        this.credentialFactory = credentialFactory;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
        return getCredential(credentialType, algorithmName, parameterSpec) != null ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
        try {
            return credentialFactory.create().castAs(credentialType, algorithmName, parameterSpec);
        }
        catch (GeneralSecurityException e) {
            throw ElytronMessages.log.unableToReadCredential(e);
        }
    }
}
