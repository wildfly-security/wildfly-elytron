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

import static java.lang.System.getSecurityManager;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.auth.jaspi._private.ElytronMessages.log;

import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.SecurityPermission;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.RegistrationListener;

import org.wildfly.security.manager.action.GetContextClassLoaderAction;

/**
 * The WildFly Elytron implementation of {@link AuthConfigFactory}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronAuthConfigFactory extends AuthConfigFactory {

    private final Map<LayerContextKey, Registration> layerContextRegistration = new HashMap<>();

    /**
     * @see javax.security.auth.message.config.AuthConfigFactory#getConfigProvider(java.lang.String, java.lang.String, javax.security.auth.message.config.RegistrationListener)
     */
    @Override
    public AuthConfigProvider getConfigProvider(String layer, String appContext, RegistrationListener listener) {
        // TODO - This is the most time sensitive method, it is called per request.
        // We may want to look at replacing the entire Map on updates so this method can query the
        // current version without locking.

        synchronized(layerContextRegistration) {
            LayerContextKey fullKey = new LayerContextKey(layer, appContext);
            Registration registration = layerContextRegistration.get(fullKey);
            // Step 1 - Exact Match
            if (registration != null) {
                if (listener != null) {
                    registration.addListener(listener);
                }
                if (registration.activeRegistration()) {
                    return registration.authConfigProvider;
                }
            } else if (listener != null) {
                // null registration but we have a listener.
                Registration listenerRegistration = new Registration(layer, appContext);
                listenerRegistration.addListener(listener);
                layerContextRegistration.put(fullKey, listenerRegistration);
            }

            // Step 2 - appContext only
            if (layer != null) {
                registration = layerContextRegistration.get(new LayerContextKey(null, appContext));
                if (registration != null && registration.activeRegistration()) {
                    return registration.authConfigProvider;
                }
            }

            // Step 3 - layer only
            if (appContext != null) {
                registration = layerContextRegistration.get(new LayerContextKey(layer, null));
                if (registration != null && registration.activeRegistration()) {
                    return registration.authConfigProvider;
                }
            }

            // Step 4 - No appContext or layer
            if (layer != null && appContext != null) {
                registration = layerContextRegistration.get(new LayerContextKey(null, null));
                if (registration != null && registration.activeRegistration()) {
                    return registration.authConfigProvider;
                }
            }
        }

        return null;
    }

    boolean matchesRegistration(final String layer, final String appContext) {
        synchronized (layerContextRegistration) {
            // Step 1 - Exact Match
            Registration registration = layerContextRegistration.get(new LayerContextKey(layer, appContext));
            if (registration != null && registration.activeRegistration()) {
                return true;
            }
            // Step 2 - appContext only
            registration = layerContextRegistration.get(new LayerContextKey(null, appContext));
            if (registration != null && registration.activeRegistration()) {
                return true;
            }
            // Step 3 - layer only
            registration = layerContextRegistration.get(new LayerContextKey(layer, null));
            if (registration != null && registration.activeRegistration()) {
                return true;
            }
            // Step 4 - No appContext or layer
            registration = layerContextRegistration.get(new LayerContextKey(null, null));
            if (registration != null && registration.activeRegistration()) {
                return true;
            }
        }

        return false;
    }

    /**
     * @see javax.security.auth.message.config.AuthConfigFactory#registerConfigProvider(javax.security.auth.message.config.AuthConfigProvider, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public String registerConfigProvider(AuthConfigProvider provider, String layer, String appContext, String description) {
        checkPermission(providerRegistrationSecurityPermission);

        return registerConfigProvider(provider, layer, appContext, description, false);
    }

    /**
     * @see javax.security.auth.message.config.AuthConfigFactory#registerConfigProvider(java.lang.String, java.util.Map, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public String registerConfigProvider(String className, Map properties, String layer, String appContext, String description) {
        // TODO [ELY-1548] We should support persisting to configuration changes made by calling this method.
        checkPermission(providerRegistrationSecurityPermission);

        AuthConfigProvider authConfigProvider = null;
        if (className != null) {
            ClassLoader classLoader = identifyClassLoader();
            try {
                Class<AuthConfigProvider> providerClass = (Class<AuthConfigProvider>) classLoader.loadClass(className);
                Constructor<AuthConfigProvider> constructor = providerClass.getConstructor(Map.class, AuthConfigFactory.class);
                authConfigProvider = constructor.newInstance(properties, null);
            } catch (Exception e) {
                throw log.unableToConstructProvider(className, e);
            }
        }

        return registerConfigProvider(authConfigProvider, layer, appContext, description, true);
    }

    /*
     * We may actually want to be calling this method when in the application server environment as we would want to say the
     * managed configuration is persistent but at the same time want to pass in a real instance.
     */

    String registerConfigProvider(AuthConfigProvider provider, String layer, String appContext, String description, boolean persistent) {
        Registration registration = null;
        List<RegistrationListener> existingListeners;
        synchronized(layerContextRegistration) {
            LayerContextKey key = new LayerContextKey(layer, appContext);
            registration = layerContextRegistration.get(key);
            if (registration == null) {
                registration = new Registration(layer, appContext);
                layerContextRegistration.put(key, registration);
                existingListeners = Collections.emptyList();
            } else {
                existingListeners = registration.clearListeners();
            }

            registration.setDescription(description);
            registration.setPersistent(persistent);
            registration.setAuthConfigProvider(provider, provider == null);
        }

        // Handle notify outside the synchronized block in case they want to re-register.
        for (RegistrationListener current : existingListeners) {
            current.notify(layer, appContext);
        }

        return registration.getRegistrationId();
    }

    /**
     * @see javax.security.auth.message.config.AuthConfigFactory#removeRegistration(java.lang.String)
     */
    @Override
    public boolean removeRegistration(String registrationId) {
        checkPermission(providerRegistrationSecurityPermission);

        String layer = null;
        String appContext = null;
        boolean removed = false;
        List<RegistrationListener> existingListeners = null;
        synchronized(layerContextRegistration) {
            Iterator<Entry<LayerContextKey, Registration>> registrationIterator = layerContextRegistration.entrySet().iterator();
            while (registrationIterator.hasNext()) {
                Entry<LayerContextKey, Registration> entry = registrationIterator.next();
                if (entry.getValue().getRegistrationId().equals(registrationId)) {
                    existingListeners = entry.getValue().clearListeners();
                    layer = entry.getKey().messageLayer;
                    appContext = entry.getKey().appContext;
                    registrationIterator.remove();
                    removed = true;
                    break;
                }
            }
        }

        // Handle notify outside the synchronized block in case they want to re-register.
        if (existingListeners != null && !existingListeners.isEmpty()) {
            for (RegistrationListener current : existingListeners) {
                current.notify(layer, appContext);
            }
        }

        return removed;
    }

    /**
     * @see javax.security.auth.message.config.AuthConfigFactory#detachListener(javax.security.auth.message.config.RegistrationListener, java.lang.String, java.lang.String)
     */
    @Override
    public String[] detachListener(RegistrationListener listener, String layer, String appContext) {
        checkNotNullParam("listener", listener);
        checkPermission(providerRegistrationSecurityPermission);
        List<String> registrationIDs = new ArrayList<>();
        synchronized (layerContextRegistration) {
            for (Registration current : layerContextRegistration.values()) {
                if ((layer == null || layer.equals(current.messageLayer)) && (appContext == null || appContext.equals(current.appContext))) {
                    if (current.removeListener(listener)) {
                        registrationIDs.add(current.getRegistrationId());
                    }
                }
            }
        }

        return registrationIDs.toArray(new String[registrationIDs.size()]);
    }

    /**
     * @see javax.security.auth.message.config.AuthConfigFactory#getRegistrationContext(java.lang.String)
     */
    @Override
    public RegistrationContext getRegistrationContext(String registrationID) {
        synchronized (layerContextRegistration) {
            for (Registration current : layerContextRegistration.values()) {
                if (current.getRegistrationId().equals(registrationID)) {
                    return current.toRegistrationContext();
                }
            }
        }

        return null;
    }

    /**
     * @see javax.security.auth.message.config.AuthConfigFactory#getRegistrationIDs(javax.security.auth.message.config.AuthConfigProvider)
     */
    @Override
    public String[] getRegistrationIDs(AuthConfigProvider provider) {
        List<String> registrationIDs = new ArrayList<>();
        synchronized (layerContextRegistration) {
            if (provider != null) {
                for (Registration current : layerContextRegistration.values()) {
                    if (provider.equals(current.authConfigProvider)) {
                        registrationIDs.add(current.registrationId);
                    }
                }
            } else {
                for (Registration current : layerContextRegistration.values()) {
                    if (current.activeRegistration()) {
                        // The registration may exist just to hold listeners.
                        registrationIDs.add(current.registrationId);
                    }
                }
            }

        }

        return registrationIDs.toArray(new String[registrationIDs.size()]);
    }

    /**
     * @see javax.security.auth.message.config.AuthConfigFactory#refresh()
     */
    @Override
    public void refresh() {
        // [ELY-1538] Dynamic loading not presently supported, once supported refresh will reload the configuration.
        checkPermission(providerRegistrationSecurityPermission);
    }

    private static void checkPermission(final SecurityPermission securityPermission) {
        SecurityManager securityManager = getSecurityManager();
        if (securityManager != null) {
            securityManager.checkPermission(securityPermission);
        }
    }

    private static ClassLoader identifyClassLoader() {
        ClassLoader classLoader = getSecurityManager() != null
                ? AccessController.doPrivileged(GetContextClassLoaderAction.getInstance())
                : GetContextClassLoaderAction.getInstance().run();

        return classLoader != null ? classLoader : ClassLoader.getSystemClassLoader();
    }

    static class Registration {
        final String registrationId = UUID.randomUUID().toString();

        private boolean nullProvider;
        private AuthConfigProvider authConfigProvider;
        private List<RegistrationListener> registrationListeners = new ArrayList<>();

        private final String appContext;
        private final String messageLayer;
        private String description;
        private boolean persistent;

        Registration(final String messageLayer, final String appContext) {
            this.messageLayer = messageLayer;
            this.appContext = appContext;
        }

        String getRegistrationId() {
            return registrationId;
        }

        void setDescription(final String description) {
            this.description = description;
        }

        void setPersistent(final boolean persistent) {
            this.persistent = persistent;
        }

        void setAuthConfigProvider(final AuthConfigProvider authConfigProvider, final boolean nullProvider) {
            this.authConfigProvider = authConfigProvider;
            this.nullProvider = authConfigProvider == null ? nullProvider : false;
        }

        AuthConfigProvider getAuthConfigProvider() {
            return authConfigProvider;
        }

        boolean isNullProvider() {
            return nullProvider;
        }

        /*
         * RegistrationListener Manipulation
         */

        void addListener(final RegistrationListener registrationListener) {
            this.registrationListeners.add(registrationListener);
        }

        boolean removeListener(final RegistrationListener registrationListener) {
            return registrationListeners.remove(registrationListener);
        }

        List<RegistrationListener> clearListeners() {
            List<RegistrationListener> currentListeners = this.registrationListeners;
            this.registrationListeners = new ArrayList<>();

            return currentListeners;
        }

        boolean activeRegistration() {
            return authConfigProvider != null || nullProvider;
        }

        RegistrationContext toRegistrationContext() {
            // We return a new instance to avoid state changes being detected by stale references.
            return activeRegistration() ? new ElytronRegistrationContext(messageLayer, appContext, description, persistent) : null;
        }

    }

    static class ElytronRegistrationContext implements RegistrationContext {

        private final String appContext;
        private final String messageLayer;
        private final  String description;
        private final boolean persistent;

        ElytronRegistrationContext(final String messageLayer, final String appContext, final String description, final boolean persistent) {
            this.messageLayer = messageLayer;
            this.appContext = appContext;
            this.description = description;
            this.persistent = persistent;
        }

        @Override
        public String getMessageLayer() {
            return messageLayer;
        }

        @Override
        public String getAppContext() {
            return appContext;
        }

        @Override
        public String getDescription() {
            return description;
        }

        @Override
        public boolean isPersistent() {
            return persistent;
        }

    }

    /*
     * The down side of a key like this is we end up with per-request object allocation to be garbage collected, the up side
     * however is we can accurately differentiate null values from the String 'null'.
     */

    static final class LayerContextKey {
        private final String messageLayer;
        private final String appContext;
        private final int hash;

        LayerContextKey(final String messageLayer, final String appContext) {
            this.messageLayer = messageLayer;
            this.appContext = appContext;

            this.hash = (messageLayer != null ? messageLayer.hashCode() : 7)
                    * (appContext != null ? appContext.hashCode() : 13);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof LayerContextKey ? equals((LayerContextKey) other) : false;
        }

        boolean equals(LayerContextKey other) {
            return (messageLayer != null ? messageLayer.equals(other.messageLayer) : other.messageLayer == null) &&
                    (appContext != null ? appContext.equals(other.appContext) : other.appContext == null);
        }

        @Override
        public int hashCode() {
            return hash;
        }

    }

}
