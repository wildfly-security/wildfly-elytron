/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.util;

import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.Set;

import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.security.manager.WildFlySecurityManager;

/**
 * A utility class for discovering SASL client and server factories.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SaslFactories {

    private SaslFactories() {
    }

    /**
     * Returns an iterator of all of the registered {@code SaslServerFactory}s where the order is based on the
     * order of the Provider registration and/or class path order.  Class path providers are listed before
     * global providers; in the event of a name conflict, the class path provider is preferred.
     *
     * @param classLoader the class loader to use
     * @param includeGlobal {@code true} to include globally registered providers, {@code false} to exclude them
     * @return the {@code Iterator} of {@code SaslServerFactory}s
     */
    public static Iterator<SaslServerFactory> getSaslServerFactories(ClassLoader classLoader, boolean includeGlobal) {
        return getFactories(SaslServerFactory.class, classLoader, includeGlobal);
    }

    /**
     * Returns an iterator of all of the registered {@code SaslServerFactory}s where the order is based on the
     * order of the Provider registration and/or class path order.
     *
     * @return the {@code Iterator} of {@code SaslServerFactory}s
     */
    public static Iterator<SaslServerFactory> getSaslServerFactories() {
        return getFactories(SaslServerFactory.class, null, true);
    }

    /**
     * Returns an iterator of all of the registered {@code SaslClientFactory}s where the order is based on the
     * order of the Provider registration and/or class path order.  Class path providers are listed before
     * global providers; in the event of a name conflict, the class path provider is preferred.
     *
     * @param classLoader the class loader to use
     * @param includeGlobal {@code true} to include globally registered providers, {@code false} to exclude them
     * @return the {@code Iterator} of {@code SaslClientFactory}s
     */
    public static Iterator<SaslClientFactory> getSaslClientFactories(ClassLoader classLoader, boolean includeGlobal) {
        return getFactories(SaslClientFactory.class, classLoader, includeGlobal);
    }

    /**
     * Returns an iterator of all of the registered {@code SaslClientFactory}s where the order is based on the
     * order of the Provider registration and/or class path order.
     *
     * @return the {@code Iterator} of {@code SaslClientFactory}s
     */
    public static Iterator<SaslClientFactory> getSaslClientFactories() {
        return getFactories(SaslClientFactory.class, null, true);
    }

    private static <T> Iterator<T> getFactories(Class<T> type, ClassLoader classLoader, boolean includeGlobal) {
        Set<T> factories = new LinkedHashSet<T>();
        final ServiceLoader<T> loader = ServiceLoader.load(type, classLoader);
        Iterator<T> iterator = loader.iterator();
        for (;;) try {
            if (! iterator.hasNext()) {
                break;
            }
            factories.add(iterator.next());
        } catch (ServiceConfigurationError ignored) {}
        if (includeGlobal) {
            Set<String> loadedClasses = new HashSet<String>();
            final String filter = type.getSimpleName() + ".";

            Provider[] providers = Security.getProviders();
            for (Provider currentProvider : providers) {
                final ClassLoader cl = WildFlySecurityManager.getClassLoaderPrivileged(currentProvider.getClass());
                for (Object currentKey : currentProvider.keySet()) {
                    if (currentKey instanceof String &&
                            ((String) currentKey).startsWith(filter) &&
                            ((String) currentKey).indexOf(' ') < 0) {
                        String className = currentProvider.getProperty((String) currentKey);
                        if (className != null && loadedClasses.add(className)) {
                            try {
                                factories.add(Class.forName(className, true, cl).asSubclass(type).newInstance());
                            } catch (ClassNotFoundException | ClassCastException | InstantiationException | IllegalAccessException e) {
                            }
                        }
                    }
                }
            }
        }
        return factories.iterator();
    }

}
