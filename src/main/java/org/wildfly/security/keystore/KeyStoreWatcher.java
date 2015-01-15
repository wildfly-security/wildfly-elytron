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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Central point for watching for modifications to KeyStores.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class KeyStoreWatcher {

    private final FileSystem fileSystem;

    private volatile Map<Path, Map<String, List<Store>>> watchedPaths = new HashMap<Path, Map<String, List<Store>>>();
    private final Map<Path, WatchKey> registrations = new HashMap<Path, WatchKey>();

    private volatile WatchService watchService;

    private static KeyStoreWatcher theWatcher = new KeyStoreWatcher();

    private KeyStoreWatcher() {
        fileSystem = FileSystems.getDefault();
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
            pathStores = new ArrayList<Store>();
        } else {
            pathRegistration = new HashMap<String, List<Store>>(pathRegistration);
            List<Store> tmpStore = pathRegistration.get(fileName);
            if (tmpStore != null) {
                // Copy the store so we can add to it without affecting any iterator.
                pathStores = new ArrayList<Store>(tmpStore);
            } else {
                pathStores = new ArrayList<Store>();
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
                Thread pollThread = new Thread(new EventTaker(), "KeyStoreWatcher Daemon");
                pollThread.setDaemon(true);
                pollThread.start();
            }
            // We use 'create' in addition to 'modify' as updates could be in the form of replacing a file.
            WatchKey key = dirPath.register(watchService,  StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);
            registrations.put(dirPath, key);
        }
    }

    synchronized void deRegister(File watchFile, Store keyStore) throws IOException {
        File canonical = watchFile.getCanonicalFile();

        File parentDir = canonical.getParentFile();
        String fileName = canonical.getName();

        Path dirPath = parentDir.toPath();

        Map<String, List<Store>> pathRegistration = watchedPaths.get(dirPath);
        List<Store> pathStores = null;
        if (pathRegistration != null) {
            pathRegistration = new HashMap<String, List<Store>>(pathRegistration);
            List<Store> tmpStores = pathRegistration.get(fileName);
            if (tmpStores != null) {
                pathStores = new ArrayList<Store>(tmpStores);
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
                WatchService watchService = KeyStoreWatcher.this.watchService;
                while (watchService != null) {
                    WatchKey key = watchService.take();
                    Path watchedPath = (Path) key.watchable();
                    Map<String, List<Store>> pathRegistration = watchedPaths.get(watchedPath);
                    Set<Store> toNotify = new HashSet<Store>();
                    if (pathRegistration != null) {
                        for (WatchEvent<?> event : key.pollEvents()) {
                            if (StandardWatchEventKinds.ENTRY_CREATE.equals(event.kind())
                                    || StandardWatchEventKinds.ENTRY_MODIFY.equals(event.kind())) {
                                Path context = (Path) event.context();
                                String name = context.getFileName().toString();
                                System.out.println("File Name " + name);
                                List<Store> stores = pathRegistration.get(name);
                                if (stores != null) {
                                    for (Store current : stores) {
                                        toNotify.add(current);
                                    }
                                }

                            } else if (StandardWatchEventKinds.OVERFLOW.equals(event.kind())) {
                                // No idea what happened so reload them all.
                                for (List<Store> stores : pathRegistration.values()) {
                                    for (Store current : stores) {
                                        toNotify.add(current);
                                    }
                                }
                            }
                        }
                    }
                    key.reset();
                    for (Store current : toNotify) {
                        current.modified();
                    }
                }
            } catch (ClosedWatchServiceException | InterruptedException e) {
                //e.printStackTrace();
            }
        }
    }

}

