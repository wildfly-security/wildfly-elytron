package org.wildfly.security.auth.client;

import org.wildfly.security.credential.store.CredentialStore;
import org.jboss.extension.elytron.expression.ElytronExpressionResolver;
import org.jboss.extension.elytron.SecretKeyCredentialStoreDefinition;
import java.util.List;

public class EncryptedExpressionConfig {
    List<CredentialStore> credentialStores;
    List<ElytronExpressionResolver> expressionResolvers;
    SecretKeyCredentialStoreDefinition secretKeyCredentialStoreDefinition
}
