/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.key;

import static java.security.AccessController.doPrivileged;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Method;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAMultiPrimePrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.function.UnaryOperator;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;

import org.wildfly.common.Assert;

/**
 * Key utility methods.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class KeyUtil {
    private KeyUtil() {}

    /**
     * Cache so that we only have to figure out a cloning strategy for a given class one time.
     */
    private static final KeyClonerCreator CLONER_CREATOR = new KeyClonerCreator();

    /**
     * Attempt to create a safe clone of the given key object.
     * This algorithm first checks to see if the key's class implements {@link Destroyable}; if not, it is returned as-is.
     * Next it checks to see if the key has been destroyed; if so, it is returned as-is.
     * Next it determines if the key actually implements the {@link Destroyable} interface; if not, it is returned as-is.
     * Then it determines if there is a public {@code clone} method that returns a compatible type; if so, that method is used.
     * Then it determines if the key implements a known key interface; if so, a raw implementation of that interface is produced.
     * Last it checks to see if the key is some other unknown {@link SecretKey} type; if so, it captures its value using a {@link SecretKeySpec}.
     * If none of these checks succeed, an exception is thrown.
     *
     * @param expectType the expected result type (must not be {@code null})
     * @param key the key object
     * @return the cloned key, or the original if the key type is not destroyable
     */
    public static <T extends Key> T cloneKey(Class<T> expectType, T key) {
        Assert.checkNotNullParam("expectType", expectType);
        if (key instanceof Destroyable) {
            // medium path
            if (((Destroyable) key).isDestroyed()) {
                return expectType.cast(key);
            } else {
                return expectType.cast(CLONER_CREATOR.get(key.getClass()).apply(key));
            }
        } else {
            // fast path
            return expectType.cast(key);
        }
    }

    private static class KeyClonerCreator extends ClassValue<UnaryOperator<Key>> {
        protected UnaryOperator<Key> computeValue(final Class<?> type) {
            // slow path
            // check to see if it is *really* destroyable
            final Method method;
            try {
                method = type.getMethod("destroy");
            } catch (NoSuchMethodException e) {
                // nope (because somehow there is no destroy method at all)
                return UnaryOperator.identity();
            }
            if (method.getDeclaringClass() == Destroyable.class) {
                // also nope
                return UnaryOperator.identity();
            }
            // now figure out how to actually transform it.
            // see if there's a clone method.
            UnaryOperator<Key> op = checkForCloneMethod(type, type);
            if (op != null) return op;
            // see if there's a copy constructor.
            op = checkForCopyCtor(type, type);
            if (op != null) return op;
            if (PrivateKey.class.isAssignableFrom(type)) {
                // some private key type...
                if (DSAPrivateKey.class.isAssignableFrom(type)) {
                    op = checkForCloneMethod(type, DSAPrivateKey.class);
                    if (op != null) return op;
                    op = checkForCopyCtor(type, DSAPrivateKey.class);
                    if (op != null) return op;
                    return RawDSAPrivateKey::new;
                } else if (ECPrivateKey.class.isAssignableFrom(type)) {
                    op = checkForCloneMethod(type, ECPrivateKey.class);
                    if (op != null) return op;
                    op = checkForCopyCtor(type, ECPrivateKey.class);
                    if (op != null) return op;
                    return RawECPrivateKey::new;
                } else if (RSAMultiPrimePrivateCrtKey.class.isAssignableFrom(type)) {
                    op = checkForCloneMethod(type, RSAMultiPrimePrivateCrtKey.class);
                    if (op != null) return op;
                    op = checkForCopyCtor(type, RSAMultiPrimePrivateCrtKey.class);
                    if (op != null) return op;
                    return RawRSAMultiPrimePrivateCrtKey::new;
                } else if (RSAPrivateKey.class.isAssignableFrom(type)) {
                    op = checkForCloneMethod(type, RSAPrivateKey.class);
                    if (op != null) return op;
                    op = checkForCopyCtor(type, RSAPrivateKey.class);
                    if (op != null) return op;
                    return RawRSAPrivateKey::new;
                } else if (DHPrivateKey.class.isAssignableFrom(type)) {
                    op = checkForCloneMethod(type, DHPrivateKey.class);
                    if (op != null) return op;
                    op = checkForCopyCtor(type, DHPrivateKey.class);
                    if (op != null) return op;
                    return RawDHPrivateKey::new;
                }
                op = checkForCloneMethod(type, PrivateKey.class);
                if (op != null) return op;
                op = checkForCopyCtor(type, PrivateKey.class);
                if (op != null) return op;
            } else if (SecretKey.class.isAssignableFrom(type)) {
                // some secret key type...
                if (PBEKey.class.isAssignableFrom(type)) {
                    op = checkForCloneMethod(type, PBEKey.class);
                    if (op != null) return op;
                    op = checkForCopyCtor(type, PBEKey.class);
                    if (op != null) return op;
                    return RawPBEKey::new;
                } else {
                    op = checkForCloneMethod(type, SecretKey.class);
                    if (op != null) return op;
                    op = checkForCopyCtor(type, SecretKey.class);
                    if (op != null) return op;
                    // best guess
                    return orig -> new SecretKeySpec(orig.getEncoded(), orig.getAlgorithm());
                }
            } else {
                op = checkForCloneMethod(type, Key.class);
                if (op != null) return op;
            }
            return orig -> {
                throw Assert.unsupported();
            };
        }

        private UnaryOperator<Key> checkForCloneMethod(final Class<?> declType, final Class<?> returnType) {
            final MethodHandles.Lookup lookup = MethodHandles.lookup();
            final MethodHandle handle = doPrivileged((PrivilegedAction<MethodHandle>) () -> {
                try {
                    return lookup.findVirtual(declType, "clone", MethodType.methodType(returnType));
                } catch (NoSuchMethodException | IllegalAccessException e) {
                    return null;
                }
            });
            return handle == null ? null : produceOp(handle);
        }

        private UnaryOperator<Key> checkForCopyCtor(final Class<?> declType, final Class<?> paramType) {
            final MethodHandles.Lookup lookup = MethodHandles.lookup();
            final MethodHandle handle = doPrivileged((PrivilegedAction<MethodHandle>) () -> {
                try {
                    return lookup.findConstructor(declType, MethodType.methodType(void.class, paramType));
                } catch (NoSuchMethodException | IllegalAccessException e) {
                    return null;
                }
            });
            return handle == null ? null : produceOp(handle);
        }

        private static UnaryOperator<Key> produceOp(final MethodHandle handle) {
            return original -> {
                try {
                    return (Key) handle.invoke(original);
                } catch (RuntimeException | Error e) {
                    throw e;
                } catch (Throwable throwable) {
                    throw new UndeclaredThrowableException(throwable);
                }
            };
        }
    }
}
