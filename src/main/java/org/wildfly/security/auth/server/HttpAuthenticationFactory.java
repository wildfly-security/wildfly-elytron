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
import static org.wildfly.security.http.HttpConstants.HOST;

import java.util.Collection;
import java.util.Collections;
import java.util.function.UnaryOperator;

import javax.security.auth.callback.CallbackHandler;

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
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.util.SecurityIdentityServerMechanismFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;

/**
 * A HTTP authentication mechanism configuration, the configuration is associated with the {@link SecurityDomain} and
 * {@link HttpServerAuthenticationMechanismFactory} for obtaining configured mechanisms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class HttpAuthenticationFactory extends AbstractMechanismAuthenticationFactory<HttpServerAuthenticationMechanism, HttpServerAuthenticationMechanismFactory, HttpAuthenticationException> {

    HttpAuthenticationFactory(final SecurityDomain securityDomain, final MechanismConfigurationSelector mechanismConfigurationSelector, final HttpServerAuthenticationMechanismFactory factory) {
        super(securityDomain, mechanismConfigurationSelector, factory);
    }

    HttpServerAuthenticationMechanism doCreate(final String name, final CallbackHandler callbackHandler, final UnaryOperator<HttpServerAuthenticationMechanismFactory> factoryTransformation) throws HttpAuthenticationException {
        return new SecurityIdentityServerMechanismFactory(factoryTransformation.apply(getFactory())).createAuthenticationMechanism(name, Collections.emptyMap(), callbackHandler);
    }

    Collection<String> getAllSupportedMechNames() {
        return asList(getFactory().getMechanismNames(Collections.emptyMap()));
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
     * Get the host name from the given {@link HttpServerRequest}.
     *
     * @param httpServerRequest the HTTP request
     * @return the host name derived from the given HTTP request
     */
    public static String getHostName(final HttpServerRequest httpServerRequest) {
        final String host = httpServerRequest.getFirstRequestHeaderValue(HOST);
        String resolvedHostName = null;
        if (host != null) {
            if (host.startsWith("[")) {
                int close = host.indexOf(']');
                if (close > 0) {
                    resolvedHostName = host.substring(0, close);
                }
            } else {
                int colon = host.lastIndexOf(':');
                resolvedHostName = colon > 0 ? host.substring(0, colon) : host;
            }
        }
        return resolvedHostName;
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
    public static final class Builder extends AbstractMechanismAuthenticationFactory.Builder<HttpServerAuthenticationMechanism, HttpServerAuthenticationMechanismFactory, HttpAuthenticationException> {

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

        public Builder setFactory(final HttpServerAuthenticationMechanismFactory factory) {
            super.setFactory(factory);
            return this;
        }

        public HttpAuthenticationFactory build() {
            return new HttpAuthenticationFactory(getSecurityDomain(), getMechanismConfigurationSelector(), getFactory());
        }
    }
}
