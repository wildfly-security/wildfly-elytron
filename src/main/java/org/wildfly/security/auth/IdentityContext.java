/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth;

import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class IdentityContext {

    private static final ThreadLocal<IdentityContext> currentIdentityContext = new ThreadLocal<IdentityContext>() {
        protected IdentityContext initialValue() {
            return EMPTY;
        }
    };

    final Map<IdentityKey<?>, SecurityIdentity> identityKeys;

    private static final IdentityContext EMPTY = new IdentityContext();

    IdentityContext() {
        identityKeys = Collections.emptyMap();
    }

    IdentityContext(final Map<IdentityKey<?>, SecurityIdentity> identityKeys) {
        this.identityKeys = identityKeys;
    }

    /**
     * Get a new, empty identity context.
     *
     * @return the new identity context
     */
    public static IdentityContext empty() {
        return EMPTY;
    }

    /**
     * Get the current thread's captured identity context.
     *
     * @return the current thread's captured identity context
     */
    public static IdentityContext captureCurrent() {
        return currentIdentityContext.get();
    }

    /**
     * Get a copy of this identity context which only includes keys given in the target list.
     *
     * @param keys the keys to include
     * @return the context copy
     */
    public IdentityContext includingOnly(IdentityKey<?>... keys) {
        if (keys == null || keys.length == 0) return EMPTY;
        final HashMap<IdentityKey<?>, SecurityIdentity> map = new HashMap<>(identityKeys.size());
        for (IdentityKey<?> key : keys) {
            final SecurityIdentity identity = identityKeys.get(key);
            if (identity != null) {
                map.put(key, identity);
            }
        }
        if (map.isEmpty()) return EMPTY;
        if (map.size() == identityKeys.size()) return this;
        if (map.size() == 1) {
            final Map.Entry<IdentityKey<?>, SecurityIdentity> entry = map.entrySet().iterator().next();
            return new IdentityContext(Collections.<IdentityKey<?>, SecurityIdentity>singletonMap(entry.getKey(), entry.getValue()));
        } else {
            return new IdentityContext(map);
        }
    }

    /**
     * Get a copy of this identity context which only includes the key given.
     *
     * @param key the key to include
     * @return the context copy
     */
    public IdentityContext includingOnly(IdentityKey<?> key) {
        if (key == null) return EMPTY;
        if (identityKeys.containsKey(key)) {
            if (identityKeys.size() == 1) {
                return this;
            } else {
                return new IdentityContext(Collections.<IdentityKey<?>, SecurityIdentity>singletonMap(key, identityKeys.get(key)));
            }
        } else {
            return EMPTY;
        }
    }

    public IdentityContext excluding(IdentityKey<?>... keys) {
        if (keys == null || keys.length == 0) return this;
        if (identityKeys.isEmpty()) return this;
        final HashMap<IdentityKey<?>, SecurityIdentity> map = new HashMap<>(identityKeys);
        for (IdentityKey<?> key : keys) {
            map.remove(key);
        }
        if (map.size() == identityKeys.size()) return this;
        if (map.size() == 1) {
            final Map.Entry<IdentityKey<?>, SecurityIdentity> entry = map.entrySet().iterator().next();
            return new IdentityContext(Collections.<IdentityKey<?>, SecurityIdentity>singletonMap(entry.getKey(), entry.getValue()));
        } else {
            return new IdentityContext(map);
        }
    }

    public IdentityContext excluding(IdentityKey<?> key) {
        if (key == null) return this;
        if (identityKeys.isEmpty() || ! identityKeys.containsKey(key)) return this;
        if (identityKeys.size() == 1) return EMPTY;
        if (identityKeys.size() == 2) {
            final Iterator<Map.Entry<IdentityKey<?>, SecurityIdentity>> iterator = identityKeys.entrySet().iterator();
            assert iterator.hasNext();
            Map.Entry<IdentityKey<?>, SecurityIdentity> item = iterator.next();
            assert iterator.hasNext();
            if (item.getKey().equals(key)) {
                item = iterator.next();
            }
            assert ! item.getKey().equals(key);
            return new IdentityContext(Collections.<IdentityKey<?>, SecurityIdentity>singletonMap(item.getKey(), item.getValue()));
        } else {
            final HashMap<IdentityKey<?>, SecurityIdentity> map = new HashMap<>(identityKeys);
            map.remove(key);
            return new IdentityContext(map);
        }
    }

    public IdentityContext mergedWith(IdentityContext other) {
        if (other == null) {
            throw new IllegalArgumentException("other is null");
        }
        final Map<IdentityKey<?>, SecurityIdentity> otherKeys = other.identityKeys;
        if (otherKeys.isEmpty()) return this;
        if (identityKeys.isEmpty()) return other;
        final HashMap<IdentityKey<?>, SecurityIdentity> map = new HashMap<IdentityKey<?>, SecurityIdentity>(otherKeys.size() + identityKeys.size());
        map.putAll(identityKeys);
        map.putAll(otherKeys);
        return new IdentityContext(map);
    }

    public <T> T run(PrivilegedAction<T> action) {
        if (action == null) {
            throw new NullPointerException("action is null");
        }
        final IdentityContext oldSubj = currentIdentityContext.get();
        if (oldSubj == this) {
            return action.run();
        }
        currentIdentityContext.set(this);
        try {
            return action.run();
        } finally {
            currentIdentityContext.set(oldSubj);
        }
    }

    public <T> T run(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        if (action == null) {
            throw new NullPointerException("action is null");
        }
        final IdentityContext oldSubj = currentIdentityContext.get();
        if (oldSubj == this) {
            try {
                return action.run();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }
        currentIdentityContext.set(this);
        try {
            try {
                return action.run();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        } finally {
            currentIdentityContext.set(oldSubj);
        }
    }

    public <T, P> T run(P parameter, ParametricPrivilegedAction<T, P> action) {
        if (action == null) {
            throw new NullPointerException("action is null");
        }
        final IdentityContext oldSubj = currentIdentityContext.get();
        if (oldSubj == this) {
            return action.run(parameter);
        }
        currentIdentityContext.set(this);
        try {
            return action.run(parameter);
        } finally {
            currentIdentityContext.set(oldSubj);
        }
    }

    public <T, P> T run(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        if (action == null) {
            throw new NullPointerException("action is null");
        }
        final IdentityContext oldSubj = currentIdentityContext.get();
        if (oldSubj == this) {
            try {
                return action.run(parameter);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }
        currentIdentityContext.set(this);
        try {
            try {
                return action.run(parameter);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        } finally {
            currentIdentityContext.set(oldSubj);
        }
    }
}
