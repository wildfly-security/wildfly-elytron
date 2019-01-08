/*
 * Copyright 2018 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.jaspi;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.Map;
import java.util.function.Supplier;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.RegistrationListener;

import org.wildfly.security.auth.server.SecurityDomain;

/**
 * An {@link AuthConfigFactory} implementation that can delegate to a backup AuthConfigFactory if the Elytron factory is unable
 * to return a provider.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class DelegatingAuthConfigFactory extends AuthConfigFactory {

    private final ElytronAuthConfigFactory elytronAuthConfigFactory;
    private final AuthConfigFactory backupAuthConfigFactory;
    private final Supplier<Boolean> delegationAllowed;

    public DelegatingAuthConfigFactory(final ElytronAuthConfigFactory elytronAuthConfigFactory, final AuthConfigFactory backupAuthConfigFactory, final Supplier<Boolean> delegationAllowed) {
        this.elytronAuthConfigFactory = checkNotNullParam("elytronAuthConfigFactory", elytronAuthConfigFactory);
        this.backupAuthConfigFactory = checkNotNullParam("backupAuthConfigFactory", backupAuthConfigFactory);
        this.delegationAllowed = delegationAllowed;

    }

    public DelegatingAuthConfigFactory(final ElytronAuthConfigFactory elytronAuthConfigFactory, final AuthConfigFactory backupAuthConfigFactory) {
        this(elytronAuthConfigFactory, backupAuthConfigFactory, () -> SecurityDomain.getCurrent() == null);
    }

    @Override
    public AuthConfigProvider getConfigProvider(String layer, String appContext, RegistrationListener listener) {
        AuthConfigProvider authConfigProvider = elytronAuthConfigFactory.getConfigProvider(layer, appContext, listener);
        if (authConfigProvider != null || elytronAuthConfigFactory.matchesRegistration(layer, appContext) || !delegationAllowed.get()) {
            return authConfigProvider;
        }

        return backupAuthConfigFactory.getConfigProvider(layer, appContext, listener);
    }

    @Override
    public String[] getRegistrationIDs(AuthConfigProvider provider) {
        String[] elytronRegistrationIds = elytronAuthConfigFactory.getRegistrationIDs(provider);
        String[] backupRegistrationIds = backupAuthConfigFactory.getRegistrationIDs(provider);

        return combine(elytronRegistrationIds, backupRegistrationIds);
    }

    @Override
    public String[] detachListener(RegistrationListener listener, String layer, String appContext) {
        String[] elytronRegistrationIds = elytronAuthConfigFactory.detachListener(listener, layer, appContext);
        String[] backupRegistrationIds = backupAuthConfigFactory.detachListener(listener, layer, appContext);

        return combine(elytronRegistrationIds, backupRegistrationIds);
    }

    @Override
    public RegistrationContext getRegistrationContext(String registrationID) {
        RegistrationContext registrationContext = elytronAuthConfigFactory.getRegistrationContext(registrationID);
        if (registrationContext == null) {
            registrationContext = backupAuthConfigFactory.getRegistrationContext(registrationID);
        }
        return registrationContext;
    }

    @Override
    public void refresh() {
        elytronAuthConfigFactory.refresh();
        backupAuthConfigFactory.refresh();
    }

    @Override
    public String registerConfigProvider(String className, Map properties, String layer, String appContext, String description) {
        return elytronAuthConfigFactory.registerConfigProvider(className, properties, layer, appContext, description);
    }

    @Override
    public String registerConfigProvider(AuthConfigProvider provider, String layer, String appContext, String description) {
        return elytronAuthConfigFactory.registerConfigProvider(provider, layer, appContext, description);
    }

    @Override
    public boolean removeRegistration(String registrationID) {
        return elytronAuthConfigFactory.removeRegistration(registrationID) || backupAuthConfigFactory.removeRegistration(registrationID);
    }

    private static String[] combine(String[] left, String[] right) {
        if (left == null) return right;
        if (right == null) return left;

        String[] result = new String[left.length + right.length];
        if (left.length > 0) {
            System.arraycopy(left, 0, result, 0, left.length);
        }
        if (right.length > 0) {
            System.arraycopy(right, 0, result, left.length, right.length);
        }

        return result;
    }

}
