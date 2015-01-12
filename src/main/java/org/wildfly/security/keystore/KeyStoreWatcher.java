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

package org.wildfly.security.keystore;

import java.io.File;
import java.io.IOException;
import java.nio.file.ClosedWatchServiceException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Central point for watching for modifications to KeyStores.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class KeyStoreWatcher {

    /*
     * Some key points: - - Could have multiple key stores in the same folder. - Could have multiple key store instances
     * interested in the same underlying store.
     *
     * To begin with lest just assume singleton, but maybe this could be replaced with a container specific version.
     */


    private final ExecutorService executor;
    private final FileSystem fileSystem;

    private volatile Map<Path, Map<String, List<Store>>> watchedPaths = new HashMap<Path, Map<String, List<Store>>>();
    private final Map<Path, WatchKey> registrations = new HashMap<Path, WatchKey>();

    private volatile WatchService watchService;

    private static KeyStoreWatcher theWatcher = new KeyStoreWatcher();

    private KeyStoreWatcher() {
        fileSystem = FileSystems.getDefault();
        executor = Executors.newCachedThreadPool();
    }

    static KeyStoreWatcher getDefault() {
        return theWatcher;
    }

    synchronized void register(File watchFile, Store keyStore) throws IOException {
        File canonical = watchFile.getCanonicalFile();

        File parentDir = canonical.getParentFile();
        String fileName = canonical.getName();

        Path dirPath = parentDir.toPath();

        boolean watchRequired = false;
        Map<String, List<Store>> pathRegistration = watchedPaths.get(dirPath);
        List<Store> pathStores = null;
        if (pathRegistration == null) {
            watchRequired = true;
            pathRegistration = new HashMap<String, List<Store>>();
            pathStores = new LinkedList<Store>();
        } else {
            pathRegistration = new HashMap<String, List<Store>>(pathRegistration);
            List<Store> tmpStore = pathRegistration.get(fileName);
            if (tmpStore != null) {
                // Copy the store so we can add to it without affecting any iterator.
                pathStores = new LinkedList<Store>(tmpStore);
            } else {
                pathStores = new LinkedList<Store>();
            }
        }

        pathStores.add(keyStore);
        pathRegistration.put(fileName, pathStores);
        Map<Path, Map<String, List<Store>>> newWatchedPaths = new HashMap<Path, Map<String, List<Store>>>(watchedPaths);
        newWatchedPaths.put(dirPath, pathRegistration);
        watchedPaths = newWatchedPaths;

        if (watchRequired) {
            if (watchService == null) {
                watchService = fileSystem.newWatchService();
                executor.execute(new EventTaker());
            }
            // We use 'create' in addition to 'modify' as updates could be in the form of replacing a file.
            WatchKey key = dirPath.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);
            registrations.put(dirPath, key);
        }
    }

    synchronized void deRegister(File watchFile, Store keyStore) throws IOException {
        File canonical = watchFile.getCanonicalFile();

        File parentDir = canonical.getParentFile();
        String fileName = canonical.getName();

        Path dirPath = parentDir.toPath();

        boolean watchRequired = false;
        Map<String, List<Store>> pathRegistration = watchedPaths.get(dirPath);
        List<Store> pathStores = null;
        if (pathRegistration != null) {
            pathRegistration = new HashMap<String, List<Store>>(pathRegistration);
            List<Store> tmpStores = pathRegistration.get(fileName);
            if (tmpStores != null) {
                pathStores = new LinkedList<Store>(tmpStores);
                Iterator<Store> storeIterator = pathStores.iterator();
                while (storeIterator.hasNext()) {
                    Store current = storeIterator.next();
                    if (keyStore == current) {
                        storeIterator.remove();
                    }
                }
                if (pathStores.isEmpty()) {
                    pathRegistration.remove(fileName);
                } else {
                    pathRegistration.put(fileName, pathStores);
                }
            }

            Map<Path, Map<String, List<Store>>> newWatchedPaths = new HashMap<Path, Map<String, List<Store>>>(watchedPaths);
            if (pathRegistration.isEmpty()) {
                newWatchedPaths.remove(dirPath);
                WatchKey key = registrations.remove(dirPath);
                if (key != null) {
                    key.cancel();
                }
                if (newWatchedPaths.isEmpty()) {
                    watchService.close();
                    watchService = null;
                }
            } else {
                newWatchedPaths.put(dirPath, pathRegistration);
            }
            watchedPaths = newWatchedPaths;
        }

    }

    interface Store {

        void modified();

    }

    private class EventTaker implements Runnable {

        @Override
        public void run() {
            try {
                while (watchService != null) {
                    WatchKey key = watchService.take();
                    Path watchedPath = (Path) key.watchable();
                    Map<String, List<Store>> pathRegistration = watchedPaths.get(watchedPath);
                    if (pathRegistration != null) {
                        for (WatchEvent<?> event : key.pollEvents()) {
                            if (StandardWatchEventKinds.ENTRY_CREATE.equals(event.kind())
                                    || StandardWatchEventKinds.ENTRY_MODIFY.equals(event.kind())) {
                                Path context = (Path) event.context();
                                String name = context.getFileName().toString();
                                List<Store> stores = pathRegistration.get(name);
                                if (stores != null) {
                                    for (Store current : stores) {
                                        executor.execute(new Notifier(current));
                                    }
                                }

                            } else if (StandardWatchEventKinds.OVERFLOW.equals(event.kind())) {
                                // No idea what happened so reload them all.
                                for (List<Store> stores : pathRegistration.values()) {
                                    for (Store current : stores) {
                                        executor.execute(new Notifier(current));
                                    }
                                }
                            }
                        }

                    }
                    key.reset();
                }
            } catch (ClosedWatchServiceException | InterruptedException e) {
                //e.printStackTrace();
            }
        }
    }

    private class Notifier implements Runnable {

        private final Store store;

        private Notifier(Store store) {
            this.store = store;
        }

        @Override
        public void run() {
            store.modified();
        }

    }
}

