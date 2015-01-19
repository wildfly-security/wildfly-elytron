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
import java.util.Collections;
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
     *
     *  Note: This is defined as 'volatile' as on writes the whole {@link Map} will be replaced.
     */
    private volatile Map<Path, Map<String, List<Store>>> watchedPaths = Collections.emptyMap();
    private final Map<Path, WatchKey> registrations = new HashMap<Path, WatchKey>();

    private volatile WatchService watchService;

    private static final KeyStoreWatcher theWatcher = new KeyStoreWatcher();

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
            // There is no existing watch of this directory so we will need to start it but only do that after the Map has been updated.
            watchRequired = true;
            pathRegistration = new HashMap<String, List<Store>>();
            pathStores = new ArrayList<Store>();
        } else {
            // We are adding to an existing Map so create a copy.
            pathRegistration = new HashMap<String, List<Store>>(pathRegistration);
            List<Store> tmpStore = pathRegistration.get(fileName);
            if (tmpStore != null) {
                // Copy the store so we can add to it without affecting any iterator.
                pathStores = new ArrayList<Store>(tmpStore);
            } else {
                pathStores = new ArrayList<Store>();
            }
        }

        /*
         * Modifications should not happen to any of these collections but to detect errors
         * in the future make all unmodifiable.
         */
        pathStores.add(keyStore);
        // The pathStores is the one we created one way or another above.
        pathRegistration.put(fileName, Collections.unmodifiableList(pathStores));
        // We are making modifications so copy watchedPaths
        Map<Path, Map<String, List<Store>>> newWatchedPaths = new HashMap<Path, Map<String, List<Store>>>(watchedPaths);
        // pathRegistration was also created one way or another above.
        newWatchedPaths.put(dirPath, Collections.unmodifiableMap(pathRegistration));
        watchedPaths = Collections.unmodifiableMap(newWatchedPaths);

        if (watchRequired) {
            if (watchService == null) {
                // Is this the very first Path to be watched, if so we are going to need a WatchService.
                watchService = fileSystem.newWatchService();
                Thread pollThread = new Thread(new EventTaker(), "KeyStoreWatcher Daemon");
                pollThread.setDaemon(true);
                pollThread.start();
            }
            // We use 'create' in addition to 'modify' as updates could be in the form of replacing a file.
            WatchKey key = dirPath.register(watchService,  StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);
            // We also need to maintain a mapping with the WatchKey so we have something we can use to Cancel the registration latser.
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
            // The act of removal means we know we will be replacing the list of keystores requiring notification, it
            // may also result in this file being no-longer monitored - either way we need a copy to work on.
            pathRegistration = new HashMap<String, List<Store>>(pathRegistration);
            List<Store> tmpStores = pathRegistration.get(fileName);
            if (tmpStores != null) {
                // Remove all references to this store from a copy of the list of stores to be notified about this file.
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
                    // Other stores are still expecting notifications.
                    pathRegistration.put(fileName, Collections.unmodifiableList(pathStores));
                }
            }

            // Copy of the watched paths so the updated collections can be added / entries removed as needed.
            Map<Path, Map<String, List<Store>>> newWatchedPaths = new HashMap<Path, Map<String, List<Store>>>(watchedPaths);
            if (pathRegistration.isEmpty()) {
                // This was the last registration watching anything in the directory specified.
                newWatchedPaths.remove(dirPath);
                // Remove and cancel the WatchKey registration.
                WatchKey key = registrations.remove(dirPath);
                if (key != null) {
                    key.cancel();
                }
                // This could also have been the last directory overall being monitored, if so the WatchService can be closed and discarded.
                if (newWatchedPaths.isEmpty()) {
                    watchService.close();
                    watchService = null;
                }
            } else {
                // Still some files to monitor so just set the updated Map for the current path.
                newWatchedPaths.put(dirPath, Collections.unmodifiableMap(pathRegistration));
            }
            // Finally set back the replacement Map.
            watchedPaths = Collections.unmodifiableMap(newWatchedPaths);
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
                    Map<String, List<Store>> pathRegistration = watchedPaths.get(watchedPath);
                    // watchedPaths is volatile, any further writes above will not affect the pathRegistration reference we just obtained.

                    // We create a list of Store implementations to notify as a single file could trigger multiple events, e.g. on Windows
                    // a rename can be seen as a CREATE followed by a MODIFY.
                    Set<Store> toNotify = new HashSet<Store>();
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
                    for (Store current : toNotify) {
                        current.modified();
                    }
                }
            } catch (ClosedWatchServiceException | InterruptedException e) {
            }
        }
    }

}

