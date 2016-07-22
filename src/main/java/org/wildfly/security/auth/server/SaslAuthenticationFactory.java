/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.auth.server;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.function.UnaryOperator;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.AlgorithmEvidence;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.AbstractDelegatingSaslServerFactory;
import org.wildfly.security.sasl.util.AuthenticationCompleteCallbackSaslServerFactory;
import org.wildfly.security.sasl.util.AuthenticationTimeoutSaslServerFactory;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.sasl.util.SecurityIdentitySaslServerFactory;
import org.wildfly.security.sasl.util.SetMechanismInformationSaslServerFactory;
import org.wildfly.security.sasl.util.TrustManagerSaslServerFactory;

/**
 * A SASL server factory configuration.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SaslAuthenticationFactory extends AbstractMechanismAuthenticationFactory<SaslServer, SaslServerFactory, SaslException> {
    private final SaslServerFactory saslServerFactory;

    SaslAuthenticationFactory(final SecurityDomain securityDomain, final MechanismConfigurationSelector mechanismConfigurationSelector, final SaslServerFactory saslServerFactory) {
        super(securityDomain, mechanismConfigurationSelector, saslServerFactory);
        this.saslServerFactory = saslServerFactory;
    }

    SaslServer doCreate(final String name, final CallbackHandler callbackHandler, final UnaryOperator<SaslServerFactory> factoryTransformation) throws SaslException {
        return new SecurityIdentitySaslServerFactory(factoryTransformation.apply(getFactory())).createSaslServer(name, "unknown", null, QUERY_ALL, callbackHandler);
    }

    Collection<String> getAllSupportedMechNames() {
        final String[] names = saslServerFactory.getMechanismNames(Collections.singletonMap(WildFlySasl.MECHANISM_QUERY_ALL, "true"));
        // todo: filter down based on SASL selection criteria
        if (names == null || names.length == 0) {
            return Collections.emptyList();
        } else if (names.length == 1) {
            return Collections.singletonList(names[0]);
        } else {
            return Arrays.asList(names);
        }
    }

    Collection<Class<? extends Evidence>> getSupportedEvidenceTypes(final String mechName) {
        return SaslMechanismInformation.getSupportedServerEvidenceTypes(mechName);
    }

    Collection<String> getSupportedEvidenceAlgorithmNames(final Class<? extends AlgorithmEvidence> evidenceType, final String mechName) {
        return SaslMechanismInformation.getSupportedServerEvidenceAlgorithms(mechName, evidenceType);
    }

    Collection<Class<? extends Credential>> getSupportedCredentialTypes(final String mechName) {
        return SaslMechanismInformation.getSupportedServerCredentialTypes(mechName);
    }

    Collection<String> getSupportedCredentialAlgorithmNames(final Class<? extends AlgorithmCredential> credentialType, final String mechName) {
        return SaslMechanismInformation.getSupportedServerCredentialAlgorithms(mechName, credentialType);
    }

    boolean usesCredentials(final String mechName) {
        return SaslMechanismInformation.needsServerCredentials(mechName);
    }

    static final Map<String, String> QUERY_ALL = Collections.singletonMap(WildFlySasl.MECHANISM_QUERY_ALL, "true");

    /**
     * Obtain a new {@link Builder} capable of building a {@link SaslAuthenticationFactory}.
     *
     * @return a new {@link Builder} capable of building a {@link SaslAuthenticationFactory}.
     */
    public static Builder builder() {
        return new Builder();
    }

     /**
     * A builder for SASL server factory configurations.
     */
    public static final class Builder extends AbstractMechanismAuthenticationFactory.Builder<SaslServer, SaslServerFactory, SaslException> {

        /**
         * Construct a new instance.
         */
        Builder() {
        }

        public Builder setSecurityDomain(final SecurityDomain securityDomain) {
            super.setSecurityDomain(securityDomain);
            return this;
        }

        public Builder setMechanismConfigurationSelector(final MechanismConfigurationSelector mechanismConfigurationSelector) {
            super.setMechanismConfigurationSelector(mechanismConfigurationSelector);
            return this;
        }

        public Builder setFactory(final SaslServerFactory factory) {
            super.setFactory(factory);
            return this;
        }

        public SaslAuthenticationFactory build() {
            AbstractDelegatingSaslServerFactory factory = new AuthenticationCompleteCallbackSaslServerFactory(new SetMechanismInformationSaslServerFactory(getFactory()));
            if (! factory.delegatesThrough(TrustManagerSaslServerFactory.class)) {
                factory = new TrustManagerSaslServerFactory(factory, null); // Use the default trust manager
            }
            factory = new AuthenticationTimeoutSaslServerFactory(factory, SecurityDomain.getScheduledExecutorService()); // Use an authentication timeout
            return new SaslAuthenticationFactory(getSecurityDomain(), getMechanismConfigurationSelector(), factory);
        }
    }
}
