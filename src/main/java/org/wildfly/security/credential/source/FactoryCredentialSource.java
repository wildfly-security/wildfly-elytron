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
        return getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec) != null ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
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
