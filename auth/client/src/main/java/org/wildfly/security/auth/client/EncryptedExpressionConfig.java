package org.wildfly.security.auth.client;


import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.source.impl.CredentialStoreCredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.provider.util.ProviderFactory;

import java.security.Provider;
import java.util.function.Supplier;


public final class EncryptedExpressionConfig {

    private static final int SET_CREDENTIAL_STORE = 0;
    private static final int SET_RESOLVER = 1;
    private static final int SET_DEFAULT_RESOLVER = 2;
    private static final Supplier<Provider[]> DEFAULT_PROVIDER_SUPPLIER = ProviderFactory.getDefaultProviderSupplier(EncryptedExpressionConfig.class.getClassLoader());

    public static EncryptedExpressionConfig empty() {
        return new EncryptedExpressionConfig();
    }

    CredentialSource credentialSource;

    EncryptedExpressionConfig() {
        this.credentialSource = null;
    }

    private EncryptedExpressionConfig(final EncryptedExpressionConfig original, final int what, final Object value) {
        this.credentialSource = what == SET_CREDENTIAL_STORE ? (CredentialSource) value : original.credentialSource;
    }

    private EncryptedExpressionConfig(final EncryptedExpressionConfig original, final EncryptedExpressionConfig other) {
        this.credentialSource = other.credentialSource;
    }

    private static <T> T getOrDefault(T value, T defVal) {
        return value != null ? value : defVal;
    }

    private static int getOrDefault(int value, int defVal) {
        return value != -1 ? value : defVal;
    }

    CredentialSource getCredentialSource() {
        return credentialSource;
    }
    public EncryptedExpressionConfig useCredentialStoreEntry(CredentialStore credentialStore, String alias) {
        Assert.checkNotNullParam("credentialStore", credentialStore);
        Assert.checkNotNullParam("alias", alias);
        CredentialStoreCredentialSource csCredentialSource = new CredentialStoreCredentialSource(credentialStore, alias);
        return useCredentials(getCredentialSource().with(csCredentialSource));
    }

    public EncryptedExpressionConfig useCredentials(CredentialSource credentials) {
        return new EncryptedExpressionConfig(this, SET_CREDENTIAL_STORE, credentials == null ? CredentialSource.NONE : credentials);
    }

    public EncryptedExpressionConfig useCredential(Credential credential) {
        if (credential == null) return this;
        final CredentialSource credentialSource = this.credentialSource;
        if (credentialSource == CredentialSource.NONE) {
            return new EncryptedExpressionConfig(this, SET_CREDENTIAL_STORE, IdentityCredentials.NONE.withCredential(credential));
        } else {
            return new EncryptedExpressionConfig(this, SET_CREDENTIAL_STORE, credentialSource.with(IdentityCredentials.NONE.withCredential(credential)));
        }
    }
}
