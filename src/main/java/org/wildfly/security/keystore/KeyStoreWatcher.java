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

    /**
     * This {@link Map} is the central point where actively watched keystores are recorded.
     *
     * The purpose of the {@link KeyStoreWatcher} is to provide updates to individual KeyStores when updates are applied,
     * however we need to work within the following constraints.
     *  - The {@link WatchService} watches directories and not individual files.
     *  - An administrator may have multiple keystores in the same directory.
     *  - Keystores could be located in different directories.
     *  - We could have multiple in-memory keystore instances backed by the same file.
     *
     *  So we have a {@link Map} where the key is a {@link Path} to the directory being monitored, the value is a further {@link Map}.
     *  On the second {@link Map} the key is the name of the keystore file within the the directory being monitored and the value is a {@link List}
     *  The {@link List} referenced by the {@link Map} is a list of all keystores that should be reloaded if a modification to the file is detected.
     */
    private final Map<Path, Map<String, List<Store>>> watchedPaths = new HashMap<Path, Map<String,List<Store>>>();
    private final Map<Path, WatchKey> registrations = new HashMap<Path, WatchKey>();

    private volatile WatchService watchService;

    private static final KeyStoreWatcher theWatcher = new KeyStoreWatcher();

    private KeyStoreWatcher() {
        fileSystem = FileSystems.getDefault();
    }

    static KeyStoreWatcher getDefault() {
        return theWatcher;
    }

    void register(File watchFile, Store keyStore) throws IOException {
        File canonical = watchFile.getCanonicalFile();

        File parentDir = canonical.getParentFile();
        String fileName = canonical.getName();

        Path dirPath = parentDir.toPath();

        synchronized (watchedPaths) {
            Map<String, List<Store>> pathRegistration = watchedPaths.get(dirPath);
            List<Store> pathStores = null;
            if (pathRegistration == null) {
                if (watchService == null) {
                    // Is this the very first Path to be watched, if so we are going to need a WatchService.
                    watchService = fileSystem.newWatchService();
                    Thread pollThread = new Thread(new EventTaker(), "KeyStoreWatcher Daemon");
                    pollThread.setDaemon(true);
                    pollThread.start();
                }
                // We use 'create' in addition to 'modify' as updates could be in the form of replacing a file.
                WatchKey key = dirPath.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);
                // We also need to maintain a mapping with the WatchKey so we have something we can use to Cancel the
                // registration latser.
                registrations.put(dirPath, key);

                pathRegistration = new HashMap<String, List<Store>>();
                watchedPaths.put(dirPath, pathRegistration);
                pathStores = new ArrayList<Store>();
                pathRegistration.put(fileName, pathStores);
            } else {
                pathStores = pathRegistration.get(fileName);
                if (pathStores == null) {
                    pathStores = new ArrayList<Store>();
                    pathRegistration.put(fileName, pathStores);
                }
            }

            pathStores.add(keyStore);
        }
    }

    void deRegister(File watchFile, Store keyStore) throws IOException {
        File canonical = watchFile.getCanonicalFile();

        File parentDir = canonical.getParentFile();
        String fileName = canonical.getName();

        Path dirPath = parentDir.toPath();

        synchronized (watchedPaths) {
            final Map<String, List<Store>> pathRegistration = watchedPaths.get(dirPath);
            if (pathRegistration != null) {
                final List<Store> pathStores = pathRegistration.get(fileName);
                if (pathStores != null) {
                    // Remove all references to this store.
                    Iterator<Store> storeIterator = pathStores.iterator();
                    while (storeIterator.hasNext()) {
                        Store current = storeIterator.next();
                        if (keyStore == current) {
                            storeIterator.remove();
                        }
                    }
                    if (pathStores.isEmpty()) {
                        pathRegistration.remove(fileName);
                    }
                }

                if (pathRegistration.isEmpty()) {
                    // This was the last registration watching anything in the directory specified.
                    watchedPaths.remove(dirPath);
                    // Remove and cancel the WatchKey registration.
                    WatchKey key = registrations.remove(dirPath);
                    if (key != null) {
                        key.cancel();
                    }
                    // This could also have been the last directory overall being monitored, if so the WatchService can be
                    // closed and discarded.
                    if (watchedPaths.isEmpty()) {
                        watchService.close();
                        watchService = null;
                    }
                }
            }
        }
    }

    interface Store {

        void modified();

    }

    private class EventTaker implements Runnable {

        @Override
        public void run() {
            try {
                WatchService watchService = null;
                // We only want to run whilst there is an active watch service.
                while ((watchService = KeyStoreWatcher.this.watchService) != null) {
                    WatchKey key = watchService.take();
                    Path watchedPath = (Path) key.watchable();

                    // We create a list of Store implementations to notify as a single file could trigger multiple events, e.g.
                    // on Windows
                    // a rename can be seen as a CREATE followed by a MODIFY.
                    Set<Store> toNotify = new HashSet<Store>();

                    synchronized (watchedPaths) {
                        Map<String, List<Store>> pathRegistration = watchedPaths.get(watchedPath);
                        // watchedPaths is volatile, any further writes above will not affect the pathRegistration reference we
                        // just obtained.

                        if (pathRegistration != null) {
                            for (WatchEvent<?> event : key.pollEvents()) {
                                if (StandardWatchEventKinds.ENTRY_CREATE.equals(event.kind())
                                        || StandardWatchEventKinds.ENTRY_MODIFY.equals(event.kind())) {
                                    Path context = (Path) event.context();
                                    String name = context.getFileName().toString();
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
                        key.reset(); // Reset the Key so subsequent modifications can be picked up.
                    }

                    for (Store current : toNotify) {
                        current.modified();
                    }
                }
            } catch (ClosedWatchServiceException | InterruptedException e) {
            }
        }
    }

}

