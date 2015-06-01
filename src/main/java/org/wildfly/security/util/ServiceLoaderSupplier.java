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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.function.Supplier;

import org.wildfly.security.util._private.Arrays2;

/**
 * A supplier which uses a service loader to find all instances of the given service, and return them as an array.  The
 * result is then cached.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class ServiceLoaderSupplier<E> implements Supplier<E[]> {

    private final Class<E> service;
    private final ClassLoader classLoader;
    private volatile E[] result;

    public ServiceLoaderSupplier(final Class<E> service, final ClassLoader classLoader) {
        this.service = service;
        this.classLoader = classLoader;
    }

    public E[] get() {
        if (result == null) {
            synchronized (this) {
                if (result == null) {
                    ArrayList<E> list = new ArrayList<>();
                    ServiceLoader<E> loader = ServiceLoader.load(service, classLoader);
                    Iterator<E> iterator = loader.iterator();
                    for (;;) try {
                        if (! iterator.hasNext()) {
                            return (result = list.toArray(Arrays2.createArray(service, list.size()))).clone();
                        }
                        list.add(iterator.next());
                    } catch (ServiceConfigurationError ignored) {}
                }
            }
        }
        return result.clone();
    }
}
