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
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAMultiPrimePrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.UnaryOperator;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;

import org.wildfly.common.Assert;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.MaskedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.OneTimePasswordAlgorithmSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;

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
     * Attempt to acquire parameters from the given key.
     *
     * @param key the key (must not be {@code null})
     * @return the parameters, or {@code null} if no known parameters are available
     */
    public static AlgorithmParameterSpec getParameters(Key key) {
        return getParameters(key, AlgorithmParameterSpec.class);
    }

    /**
     * Attempt to acquire parameters of the given type from the given key.
     *
     * @param key the key (must not be {@code null})
     * @param paramSpecClass the parameter specification class (must not be {@code null})
     * @param <P> the parameter specification type
     * @return the parameters, or {@code null} if no known parameters of the given type are available
     */
    public static <P extends AlgorithmParameterSpec> P getParameters(Key key, Class<P> paramSpecClass) {
        if (key instanceof Password) {
            final AlgorithmParameterSpec parameterSpec = ((Password) key).getParameterSpec();
            return paramSpecClass.isInstance(parameterSpec) ? paramSpecClass.cast(parameterSpec) : null;
        } else if (key instanceof RSAKey && paramSpecClass.isAssignableFrom(RSAParameterSpec.class)) {
            return paramSpecClass.cast(new RSAParameterSpec((RSAKey) key));
        } else if (key instanceof DSAKey && paramSpecClass.isAssignableFrom(DSAParams.class)) {
            return paramSpecClass.cast(((DSAKey) key).getParams());
        } else if (key instanceof ECKey && paramSpecClass.isAssignableFrom(ECParameterSpec.class)) {
            return paramSpecClass.cast(((ECKey) key).getParams());
        } else if (key instanceof DHKey && paramSpecClass.isAssignableFrom(DHParameterSpec.class)) {
            return paramSpecClass.cast(((DHKey) key).getParams());
        } else if (key instanceof PBEKey && paramSpecClass.isAssignableFrom(PBEParameterSpec.class)) {
            final PBEKey pbeKey = (PBEKey) key;
            // TODO: we miss the IV here
            return paramSpecClass.cast(new PBEParameterSpec(pbeKey.getSalt(), pbeKey.getIterationCount()));
        } else {
            return null;
        }
    }

    /**
     * Determine if the given key has parameters which match the given parameters.
     *
     * @param key the key (must not be {@code null})
     * @param parameters the parameters (must not be {@code null})
     * @return {@code true} if the parameters match, {@code false} otherwise
     */
    public static boolean hasParameters(final Key key, final AlgorithmParameterSpec parameters) {
        Assert.checkNotNullParam("key", key);
        Assert.checkNotNullParam("parameters", parameters);
        final AlgorithmParameterSpec keyParameters = getParameters(key, AlgorithmParameterSpec.class);
        return keyParameters != null && parametersEqual(keyParameters, parameters);
    }

    /**
     * Attempt to determine if two algorithm parameter specifications are equal.  This method will return {@code true}
     * if the parameters are definitely the same, or {@code false} if they are not definitely equal or equivalency cannot be determined.
     *
     * @param p1 the first parameter specification (must not be {@code null})
     * @param p2 the second parameter specification (must not be {@code null})
     * @return {@code true} if the parameters are definitely equal, {@code false} otherwise
     */
    public static boolean parametersEqual(final AlgorithmParameterSpec p1, final AlgorithmParameterSpec p2) {
        Assert.checkNotNullParam("p1", p1);
        Assert.checkNotNullParam("p2", p2);
        if (p1 instanceof DSAParams && p2 instanceof DSAParams) {
            final DSAParams dsa1 = (DSAParams) p1;
            final DSAParams dsa2 = (DSAParams) p2;
            return Objects.equals(dsa1.getG(), dsa2.getG()) && Objects.equals(dsa1.getP(), dsa2.getP()) && Objects.equals(dsa1.getQ(), dsa2.getQ());
        } else if (p1 instanceof ECParameterSpec && p2 instanceof ECParameterSpec) {
            final ECParameterSpec ec1 = (ECParameterSpec) p1;
            final ECParameterSpec ec2 = (ECParameterSpec) p2;
            return ec1.getCofactor() == ec2.getCofactor() && Objects.equals(ec1.getCurve(), ec2.getCurve())
                && Objects.equals(ec1.getGenerator(), ec2.getGenerator()) && Objects.equals(ec1.getOrder(), ec2.getOrder());
        } else if (p1 instanceof DHParameterSpec && p2 instanceof DHParameterSpec) {
            final DHParameterSpec dh1 = (DHParameterSpec) p1;
            final DHParameterSpec dh2 = (DHParameterSpec) p2;
            return dh1.getL() == dh2.getL() && Objects.equals(dh1.getP(), dh2.getP()) && Objects.equals(dh1.getG(), dh2.getG());
        } else if (p1 instanceof PBEParameterSpec && p2 instanceof PBEParameterSpec) {
            final PBEParameterSpec pbe1 = (PBEParameterSpec) p1;
            final PBEParameterSpec pbe2 = (PBEParameterSpec) p2;
            final AlgorithmParameterSpec param1 = pbe1.getParameterSpec();
            final AlgorithmParameterSpec param2 = pbe2.getParameterSpec();
            return pbe1.getIterationCount() == pbe2.getIterationCount() && Arrays.equals(pbe1.getSalt(), pbe2.getSalt()) && (param1 == null ? param2 == null : param2 != null && parametersEqual(param1, param2));
        } else if (p1 instanceof IvParameterSpec && p2 instanceof IvParameterSpec) {
            final IvParameterSpec iv1 = (IvParameterSpec) p1;
            final IvParameterSpec iv2 = (IvParameterSpec) p2;
            return Arrays.equals(iv1.getIV(), iv2.getIV());
        } else {
            // best effort
            return p1.equals(p2);
        }
    }

    /**
     * Attempt to get a stable hash code for the given parameter specification.  If a stable hash code cannot be acquired,
     * the hash code of the class is returned, which results in correct (if non-optimal) behavior.  If the parameter
     * is {@code null}, a hash code of zero is returned.
     *
     * @param param the parameter specification
     * @return the hash code
     */
    public static int parametersHashCode(final AlgorithmParameterSpec param) {
        if (param == null) {
            return 0;
        } else if (param instanceof DSAParams) {
            final DSAParams dsaParams = (DSAParams) param;
            return Objects.hash(dsaParams.getG(), dsaParams.getP(), dsaParams.getQ());
        } else if (param instanceof ECParameterSpec) {
            final ECParameterSpec ecSpec = (ECParameterSpec) param;
            return ecSpec.getCofactor() * 31 + Objects.hash(ecSpec.getCurve(), ecSpec.getGenerator(), ecSpec.getOrder());
        } else if (param instanceof DHParameterSpec) {
            final DHParameterSpec dhSpec = (DHParameterSpec) param;
            return dhSpec.getL() * 31 + Objects.hash(dhSpec.getP(), dhSpec.getG());
        } else if (param instanceof PBEParameterSpec) {
            final PBEParameterSpec pbeSpec = (PBEParameterSpec) param;
            final AlgorithmParameterSpec parameterSpec = pbeSpec.getParameterSpec();
            return (pbeSpec.getIterationCount() * 31 + Arrays.hashCode(pbeSpec.getSalt())) * 31 + parametersHashCode(parameterSpec);
        } else if (param instanceof IvParameterSpec) {
            return Arrays.hashCode(((IvParameterSpec) param).getIV());
        } else if (param instanceof RSAParameterSpec
                || param instanceof IteratedSaltedPasswordAlgorithmSpec
                || param instanceof IteratedPasswordAlgorithmSpec
                || param instanceof SaltedPasswordAlgorithmSpec
                || param instanceof DigestPasswordAlgorithmSpec
                || param instanceof MaskedPasswordAlgorithmSpec
                || param instanceof OneTimePasswordAlgorithmSpec
        ) {
            // our types all have proper hash codes
            return param.hashCode();
        } else {
            return param.getClass().hashCode();
        }
    }

    /**
     * Attempt to determine if the two keys have the same parameters.  This method returns {@code true} if the keys
     * definitely have the same parameters, or {@code false} if they do not or if parameter equivalency cannot be determined.
     *
     * @param key1 the first key (must not be {@code null})
     * @param key2 the second key (must not be {@code null})
     * @return {@code true} if the parameters are definitely equal, {@code false} otherwise
     */
    public static boolean hasSameParameters(final Key key1, final Key key2) {
        Assert.checkNotNullParam("key1", key1);
        Assert.checkNotNullParam("key2", key2);
        final AlgorithmParameterSpec param1 = getParameters(key1, AlgorithmParameterSpec.class);
        final AlgorithmParameterSpec param2 = getParameters(key2, AlgorithmParameterSpec.class);
        return param1 == null && param2 == null || param1 != null && param2 != null && parametersEqual(param1, param2);
    }

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
