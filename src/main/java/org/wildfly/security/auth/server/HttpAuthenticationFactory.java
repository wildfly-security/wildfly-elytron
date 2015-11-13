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

import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.common.Assert;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.AlgorithmEvidence;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;

/**
 * A HTTP authentication mechanism configuration, the configuration is associated with the {@link SecurityDomain} and
 * {@link HttpServerAuthenticationMechanismFactory} for obtaining configured mechanisms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class HttpAuthenticationFactory extends AbstractMechanismAuthenticationFactory<HttpServerAuthenticationMechanism, HttpAuthenticationException> {

    private final HttpServerAuthenticationMechanismFactory mechanismFactory;

    HttpAuthenticationFactory(final SecurityDomain securityDomain, final Map<String, MechanismConfiguration> mechanismConfigurations, final HttpServerAuthenticationMechanismFactory mechanismFactory) {
        super(securityDomain, mechanismConfigurations);
        this.mechanismFactory = mechanismFactory;
    }

    HttpServerAuthenticationMechanism doCreate(final String name, final CallbackHandler callbackHandler) throws HttpAuthenticationException {
        return mechanismFactory.createAuthenticationMechanism(name, Collections.emptyMap(), callbackHandler);
    }

    Collection<String> getAllSupportedMechNames() {
        return asList(mechanismFactory.getMechanismNames(Collections.emptyMap()));
    }

    // TODO: at some point these should no longer be hard-coded

    Collection<Class<? extends Evidence>> getSupportedEvidenceTypes(final String mechName) {
        switch (mechName) {
            case HttpConstants.BASIC_NAME: {
                return singleton(PasswordGuessEvidence.class);
            }
            default: {
                return emptySet();
            }
        }
    }

    Collection<String> getSupportedEvidenceAlgorithmNames(final Class<? extends AlgorithmEvidence> evidenceType, final String mechName) {
        return emptySet();
    }

    Collection<Class<? extends Credential>> getSupportedCredentialTypes(final String mechName) {
        switch (mechName) {
            case HttpConstants.BASIC_NAME:
            case "DIGEST": {
                return singleton(PasswordCredential.class);
            }
            default: {
                return emptySet();
            }
        }
    }

    Collection<String> getSupportedCredentialAlgorithmNames(final Class<? extends AlgorithmCredential> credentialType, final String mechName) {
        switch (mechName) {
            case HttpConstants.BASIC_NAME: {
                return singleton("*");
            }
            case "DIGEST": {
                return asList(ClearPassword.ALGORITHM_CLEAR, DigestPassword.ALGORITHM_DIGEST_MD5);
            }
            default: {
                return emptySet();
            }
        }
    }

    boolean usesCredentials(final String mechName) {
        switch (mechName) {
            case HttpConstants.BASIC_NAME:
            case "DIGEST": {
                return true;
            }
            default: {
                return false;
            }
        }
    }

    /**
     * Get the {@link HttpServerAuthenticationMechanismFactory} associated with this configuration.
     *
     * @return the {@link HttpServerAuthenticationMechanismFactory} associated with this configuration.
     */
    public HttpServerAuthenticationMechanismFactory getMechanismFactory() {
        return mechanismFactory;
    }

    /**
     * Obtain a new {@link Builder} capable of building a {@link HttpAuthenticationFactory}.
     *
     * @return a new {@link Builder} capable of building a {@link HttpAuthenticationFactory}.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for SASL server factory configurations.
     */
    public static final class Builder extends AbstractMechanismAuthenticationFactory.Builder<HttpServerAuthenticationMechanism, HttpAuthenticationException> {
        private HttpServerAuthenticationMechanismFactory httpServerAuthenticationMechanismFactory = null; // TODO: empty factory

        /**
         * Construct a new instance.
         */
        Builder() {
        }

        public Builder setSecurityDomain(final SecurityDomain securityDomain) {
            super.setSecurityDomain(securityDomain);
            return this;
        }

        public Builder addMechanism(final String mechanismName, final MechanismConfiguration mechanismConfiguration) {
            super.addMechanism(mechanismName, mechanismConfiguration);
            return this;
        }

        /**
         * Set the HTTP server authentication mechanism factory to use.
         *
         * @param httpServerAuthenticationMechanismFactory the factory (may not be {@code null})
         */
        public Builder setHttpServerAuthenticationMechanismFactory(final HttpServerAuthenticationMechanismFactory httpServerAuthenticationMechanismFactory) {
            Assert.checkNotNullParam("httpServerAuthenticationMechanismFactory", httpServerAuthenticationMechanismFactory);
            this.httpServerAuthenticationMechanismFactory = httpServerAuthenticationMechanismFactory;
            return this;
        }

        public HttpAuthenticationFactory build() {
            return new HttpAuthenticationFactory(getSecurityDomain(), getMechanismConfigurations(), httpServerAuthenticationMechanismFactory);
        }
    }
}
