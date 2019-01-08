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

package org.wildfly.security.util;

import org.wildfly.common.array.Arrays2;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.function.Supplier;

/**
 * A supplier which uses a service loader to find all instances of the given service, and return them as an array.  The
 * result is then cached.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class ServiceLoaderSupplier<E> implements Supplier<E[]> {

    private final Class<E> service;
    final ClassLoader classLoader;
    private int hashCode;
    private volatile E[] result;
    private final AccessControlContext acc;

    public ServiceLoaderSupplier(final Class<E> service, final ClassLoader classLoader) {
        this.service = service;
        this.classLoader = classLoader;
        this.acc = AccessController.getContext() ;
    }

    public E[] get() {
        if (result == null) {
            synchronized (this) {
                if (result == null) {
                    if (System.getSecurityManager() != null) {
                        result = AccessController.doPrivileged((PrivilegedAction<E[]>) () -> loadServices(service, classLoader), acc);
                    } else {
                        result = loadServices(service, classLoader);
                    }
                }
            }
        }
        return result.clone();
    }

    E[] loadServices(final Class<E> service, final ClassLoader classLoader) {
        ArrayList<E> list = new ArrayList<>();
        ServiceLoader<E> loader = ServiceLoader.load(service, classLoader);
        Iterator<E> iterator = loader.iterator();
        for (;;) try {
            if (! iterator.hasNext()) {
                return list.toArray(Arrays2.createArray(service, list.size()));
            }
            list.add(iterator.next());
        } catch (ServiceConfigurationError ignored) {
            // explicitly ignored
        }
    }

    public int hashCode() {
        int hc = hashCode;
        if (hc == 0) {
            hc = service.hashCode() * 19 + (classLoader != null ? classLoader.hashCode() : 0);
            if (hc == 0) hc = 1;
            return hashCode = hc;
        }
        return hc;
    }

    public boolean equals(final Object obj) {
        return obj instanceof ServiceLoaderSupplier && equals((ServiceLoaderSupplier<?>) obj);
    }

    private boolean equals(final ServiceLoaderSupplier<?> other) {
        return other == this || other.service == service && other.classLoader == classLoader;
    }
}
