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

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.common.Assert;

abstract class AbstractMechanismAuthenticationFactory<M, E extends Exception> implements MechanismAuthenticationFactory<M,E> {

    private final SecurityDomain securityDomain;
    private final Map<String, MechanismConfiguration> mechanismConfigurations;

    AbstractMechanismAuthenticationFactory(final SecurityDomain securityDomain, final Map<String, MechanismConfiguration> mechanismConfigurations) {
        this.securityDomain = securityDomain;
        this.mechanismConfigurations = mechanismConfigurations;
    }

    SecurityDomain getSecurityDomain() {
        return securityDomain;
    }

    public M createMechanism(String name) throws E {
        MechanismConfiguration configuration = mechanismConfigurations.get(name);
        if (configuration == null) {
            configuration = MechanismConfiguration.EMPTY;
        }
        return doCreate(name, new ServerAuthenticationContext(securityDomain, configuration).createCallbackHandler());
    }

    abstract M doCreate(String name, CallbackHandler callbackHandler) throws E;

    public Collection<String> getMechanismNames() {
        final Collection<String> names = new LinkedHashSet<>();
        for (String mechName : getAllSupportedMechNames()) {
            MechanismConfiguration mechConfig = mechanismConfigurations.get(mechName);
            if (mechConfig == null) {
                continue;
            }
            final Supplier<List<String>> supplier = mechConfig.getCredentialNameSupplier();
            final Collection<String> credentials = new LinkedHashSet<>();
            if (supplier != null) {
                credentials.addAll(supplier.get());
            }
            for (String mechRealmName : mechConfig.getMechanismRealmNames()) {
                MechanismRealmConfiguration mechRealm = mechConfig.getMechanismRealmConfiguration(mechRealmName);
                final Supplier<List<String>> supplier1 = mechRealm.getCredentialNameSupplier();
                if (supplier1 != null) {
                    credentials.addAll(supplier1.get());
                }
            }
            boolean supported = false;
            for (String credential : credentials) {
                if (securityDomain.getCredentialSupport(credential).mayBeVerifiable() || securityDomain.getCredentialSupport(credential).mayBeObtainable()) {
                    supported = true;
                    break;
                }
            }
            if (supported) {
                names.add(mechName);
            }
        }
        return names;
    }

    abstract Collection<String> getAllSupportedMechNames();

    abstract static class Builder<M, E extends Exception> implements MechanismAuthenticationFactory.Builder<M,E> {
        private SecurityDomain securityDomain;
        private Map<String, MechanismConfiguration> mechanismConfigurations = new LinkedHashMap<>();

        Builder() {
        }

        public Builder<M, E> setSecurityDomain(final SecurityDomain securityDomain) {
            Assert.checkNotNullParam("securityDomain", securityDomain);
            this.securityDomain = securityDomain;
            return this;
        }

        public Builder<M, E> addMechanism(String mechanismName, MechanismConfiguration mechanismConfiguration) {
            Assert.checkNotNullParam("mechanismName", mechanismName);
            Assert.checkNotNullParam("mechanismConfiguration", mechanismConfiguration);
            mechanismConfigurations.put(mechanismName, mechanismConfiguration);
            return this;
        }

        SecurityDomain getSecurityDomain() {
            return securityDomain;
        }

        Map<String, MechanismConfiguration> getMechanismConfigurations() {
            return mechanismConfigurations;
        }
    }


}
