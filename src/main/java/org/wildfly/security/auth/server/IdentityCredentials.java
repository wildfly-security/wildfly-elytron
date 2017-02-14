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

package org.wildfly.security.auth.server;

import static org.wildfly.common.math.HashMath.multiHashOrdered;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

import org.wildfly.common.Assert;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.util.EnumerationIterator;

/**
 * The public or private credentials retained by an identity, which can be used for authentication forwarding.  This
 * credentials set can contain zero or one credential of a given type and algorithm name.  If the credential type
 * does not support algorithm names, then the set can contain zero or one credential of that type.  The credential
 * set may be iterated; iteration order is not prescribed and may change if the implementation is changed.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class IdentityCredentials implements Iterable<Credential>, CredentialSource {
    IdentityCredentials() {
    }

    /**
     * Determine whether a credential of the given type is present in this set.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @return {@code true} if a matching credential is contained in this set, {@code false} otherwise
     */
    public final boolean contains(Class<? extends Credential> credentialType) {
        return contains(credentialType, null);
    }

    @Override
    public final SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
        return contains(credentialType, algorithmName, parameterSpec) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public final SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) {
        return contains(credentialType, algorithmName) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public final SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType) {
        return contains(credentialType) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    /**
     * Determine whether a credential of the given type and algorithm are present in this set.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type
     * does not support algorithm names
     * @param parameterSpec the parameter specification or {@code null} if any parameter specification is acceptable
     * @return {@code true} if a matching credential is contained in this set, {@code false} otherwise
     */
    public abstract boolean contains(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec);

    /**
     * Determine whether a credential of the given type and algorithm are present in this set.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type
     * does not support algorithm names
     * @return {@code true} if a matching credential is contained in this set, {@code false} otherwise
     */
    public final boolean contains(Class<? extends Credential> credentialType, String algorithmName) {
        Assert.checkNotNullParam("credentialType", credentialType);
        return contains(credentialType, algorithmName, null);
    }

    /**
     * Determine whether a credential of the type, algorithm, and parameters of the given credential is present in this set.
     *
     * @param credential the credential to check against (must not be {@code null})
     * @return {@code true} if a matching credential is contained in this set, {@code false} otherwise
     */
    public final boolean containsMatching(Credential credential) {
        Assert.checkNotNullParam("credential", credential);
        if (credential instanceof AlgorithmCredential) {
            final AlgorithmCredential algorithmCredential = (AlgorithmCredential) credential;
            return contains(credential.getClass(), algorithmCredential.getAlgorithm(), algorithmCredential.getParameters());
        } else {
            return contains(credential.getClass(), null, null);
        }
    }

    /**
     * Acquire a credential of the given type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param <C> the credential type
     * @return the credential, or {@code null} if no such credential exists
     */
    @Override
    public final <C extends Credential> C getCredential(Class<C> credentialType) {
        return getCredential(credentialType, null, null);
    }

    /**
     * Acquire a credential of the given type and algorithm name.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type
     * does not support algorithm names
     * @param <C> the credential type
     * @return the credential, or {@code null} if no such credential exists
     */
    @Override
    public final <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) {
        return getCredential(credentialType, algorithmName, null);
    }

    /**
     * Acquire a credential of the given type and algorithm name.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type
     * does not support algorithm names
     * @param parameterSpec the parameter specification or {@code null} if any parameter specification is acceptable
     * @param <C> the credential type
     *
     * @return the credential, or {@code null} if no such credential exists
     */
    @Override
    public abstract <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec);

    /**
     * Apply the given function to the acquired credential, if it is set and of the given type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param function the function to apply (must not be {@code null})
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the criteria are not met
     */
    @Override
    public final <C extends Credential, R> R applyToCredential(Class<C> credentialType, Function<C, R> function) {
        final Credential credential = getCredential(credentialType);
        return credential == null ? null : credential.castAndApply(credentialType, function);
    }


    /**
     * Apply the given function to the acquired credential, if it is set and of the given type and algorithm.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name
     * @param function the function to apply (must not be {@code null})
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the criteria are not met
     */
    @Override
    public final <C extends Credential, R> R applyToCredential(Class<C> credentialType, String algorithmName, Function<C, R> function) {
        final Credential credential = getCredential(credentialType, algorithmName);
        return credential == null ? null : credential.castAndApply(credentialType, algorithmName, function);
    }

    /**
     * Apply the given function to the acquired credential, if it is set and of the given type and algorithm.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name
     * @param function the function to apply (must not be {@code null})
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the criteria are not met
     */
    @Override
    public <C extends Credential, R> R applyToCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec, final Function<C, R> function) {
        final Credential credential = getCredential(credentialType, algorithmName, parameterSpec);
        return credential == null ? null : credential.castAndApply(credentialType, algorithmName, parameterSpec, function);
    }

    /**
     * Return a copy of this credential set, but with the given credential added to it.
     *
     * @param credential the credential to append (must not be {@code null})
     * @return the new credential set (not {@code null})
     */
    public abstract IdentityCredentials withCredential(Credential credential);

    /**
     * Return a copy of this credential set with the given credential set added to it.
     *
     * @param other the credential set to append (must not be {@code null})
     * @return the new credential set (not {@code null})
     */
    public abstract IdentityCredentials with(IdentityCredentials other);

    /**
     * Return a copy of this credential set without any credentials with a type, algorithm name, and parameters matching that of the
     * given credential.  If the credential type, algorithm name, and parameters are not found in this set, return this instance.
     *
     * @param credential the credential to match against (must not be {@code null})
     * @return the new credential set (not {@code null})
     */
    public IdentityCredentials withoutMatching(Credential credential) {
        Assert.checkNotNullParam("credential", credential);
        return without(credential::matches);
    }

    /**
     * Return a copy of this credential set without any credentials of the given type.  If the credential type is not
     * found in this set, return this instance.
     *
     * @param credentialType the credential type to remove (must not be {@code null})
     * @return the new credential set (not {@code null})
     */
    public final IdentityCredentials without(Class<? extends Credential> credentialType) {
        Assert.checkNotNullParam("credentialType", credentialType);
        return without(credentialType::isInstance);
    }

    /**
     * Return a copy of this credential set without any credentials of the given type and algorithm name.  If the
     * credential type and algorithm name is not found in this set, return this instance.
     *
     * @param credentialType the credential type to remove (must not be {@code null})
     * @param algorithmName the algorithm name to remove, or {@code null} to match any algorithm name
     * @return the new credential set (not {@code null})
     */
    public final IdentityCredentials without(final Class<? extends Credential> credentialType, final String algorithmName) {
        Assert.checkNotNullParam("credentialType", credentialType);
        return without(credentialType, algorithmName, null);
    }

    public IdentityCredentials without(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
        Assert.checkNotNullParam("credentialType", credentialType);
        return without(c -> c.matches(credentialType, algorithmName, parameterSpec));
    }

    /**
     * Return a copy of this credential set without any credentials that match the predicate.  If no credentials match
     * the predicate, return this instance.
     *
     * @param predicate the predicate to test (must not be {@code null})
     * @return the new credential set (not {@code null})
     */
    public abstract IdentityCredentials without(Predicate<? super Credential> predicate);

    /**
     * Return a copy of this credential set without any credentials of the given type that match the predicate.  If no credentials match
     * the predicate, return this instance.
     *
     * @param credentialType the credential type class
     * @param predicate the predicate to test (must not be {@code null})
     * @param <C> the credential type
     * @return the new credential set (not {@code null})
     */
    public final <C extends Credential> IdentityCredentials without(Class<C> credentialType, Predicate<? super C> predicate) {
        return without(c -> credentialType.isInstance(c) && predicate.test(credentialType.cast(c)));
    }

    /**
     * Get a {@link Spliterator} for this credential set.
     *
     * @return the spliterator (not {@code null})
     */
    public Spliterator<Credential> spliterator() {
        return Spliterators.spliterator(iterator(), size(), Spliterator.IMMUTABLE | Spliterator.DISTINCT | Spliterator.NONNULL | Spliterator.ORDERED | Spliterator.SIZED);
    }

    /**
     * Get the size of this credential set.
     *
     * @return the size of this credential set
     */
    public abstract int size();

    /**
     * The empty credentials object.
     */
    public static final IdentityCredentials NONE = new IdentityCredentials() {
        public boolean contains(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
            Assert.checkNotNullParam("credentialType", credentialType);
            return false;
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
            Assert.checkNotNullParam("credentialType", credentialType);
            return null;
        }

        public IdentityCredentials with(final IdentityCredentials other) {
            Assert.checkNotNullParam("other", other);
            return other;
        }

        public IdentityCredentials withCredential(final Credential credential) {
            Assert.checkNotNullParam("credential", credential);
            return new One(credential);
        }

        public CredentialSource with(final CredentialSource other) {
            Assert.checkNotNullParam("other", other);
            return other;
        }

        public Iterator<Credential> iterator() {
            return Collections.emptyIterator();
        }

        public <C extends Credential, R> R applyToCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec, final Function<C, R> function) {
            Assert.checkNotNullParam("credentialType", credentialType);
            return null;
        }

        public IdentityCredentials withoutMatching(final Credential credential) {
            Assert.checkNotNullParam("credential", credential);
            return this;
        }

        public IdentityCredentials without(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
            Assert.checkNotNullParam("credentialType", credentialType);
            return this;
        }

        public IdentityCredentials without(final Predicate<? super Credential> predicate) {
            Assert.checkNotNullParam("predicate", predicate);
            return this;
        }

        public Spliterator<Credential> spliterator() {
            return Spliterators.emptySpliterator();
        }

        public void forEach(final Consumer<? super Credential> action) {
            Assert.checkNotNullParam("action", action);
        }

        public int size() {
            return 0;
        }

        public int hashCode() {
            return 0;
        }

        public boolean equals(Object o) {
            return o == this;
        }
    };

    static class One extends IdentityCredentials {
        private final Credential credential;

        One(final Credential credential) {
            this.credential = credential;
        }

        public boolean contains(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
            Assert.checkNotNullParam("credentialType", credentialType);
            return credential.matches(credentialType, algorithmName, parameterSpec);
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
            Assert.checkNotNullParam("credentialType", credentialType);
            return credential.matches(credentialType, algorithmName, parameterSpec) ? credentialType.cast(credential.clone()) : null;
        }

        public IdentityCredentials withCredential(final Credential credential) {
            Assert.checkNotNullParam("credential", credential);
            if (this.credential.matches(credential)) {
                return new One(credential);
            } else {
                return new Two(this.credential, credential);
            }
        }

        public IdentityCredentials with(final IdentityCredentials other) {
            Assert.checkNotNullParam("other", other);
            if (other == NONE) {
                return this;
            } else if (other instanceof One) {
                return withCredential(((One) other).credential);
            } else {
                return other.with(this);
            }
        }

        public CredentialSource with(final CredentialSource other) {
            Assert.checkNotNullParam("other", other);
            if (other instanceof IdentityCredentials) {
                return with((IdentityCredentials) other);
            } else {
                return super.with(other);
            }
        }

        public Iterator<Credential> iterator() {
            return EnumerationIterator.over(credential);
        }

        public <C extends Credential, R> R applyToCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec, final Function<C, R> function) {
            Assert.checkNotNullParam("credentialType", credentialType);
            return credential.castAndApply(credentialType, algorithmName, parameterSpec, function);
        }

        public IdentityCredentials withoutMatching(final Credential credential) {
            Assert.checkNotNullParam("credential", credential);
            return this.credential.matches(credential) ? NONE : this;
        }

        public IdentityCredentials without(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
            Assert.checkNotNullParam("credentialType", credentialType);
            return credential.matches(credentialType, algorithmName, parameterSpec) ? NONE : this;
        }

        public IdentityCredentials without(final Predicate<? super Credential> predicate) {
            Assert.checkNotNullParam("predicate", predicate);
            return predicate.test(credential) ? NONE : this;
        }

        public void forEach(final Consumer<? super Credential> action) {
            Assert.checkNotNullParam("action", action);
            action.accept(credential);
        }

        public int size() {
            return 1;
        }

        public int hashCode() {
            return typeHash(credential);
        }

        public boolean equals(final Object obj) {
            return obj instanceof One && ((One) obj).credential.equals(credential);
        }
    }

    static class Two extends IdentityCredentials {
        private final Credential credential1;
        private final Credential credential2;

        Two(final Credential credential1, final Credential credential2) {
            this.credential1 = credential1;
            this.credential2 = credential2;
        }

        public boolean contains(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
            Assert.checkNotNullParam("credentialType", credentialType);
            return credential1.matches(credentialType, algorithmName, parameterSpec) || credential2.matches(credentialType, algorithmName, parameterSpec);
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
            Assert.checkNotNullParam("credentialType", credentialType);
            return credential1.matches(credentialType, algorithmName, parameterSpec) ? credentialType.cast(credential1.clone()) :
                   credential2.matches(credentialType, algorithmName, parameterSpec) ? credentialType.cast(credential2.clone()) : null;
        }

        public IdentityCredentials withCredential(final Credential credential) {
            Assert.checkNotNullParam("credential", credential);
            if (credential.matches(credential1)) {
                return new Two(credential2, credential);
            } else if (credential.matches(credential2)) {
                return new Two(credential1, credential);
            } else {
                return new Many(credential1, credential2, credential);
            }
        }

        public IdentityCredentials with(final IdentityCredentials other) {
            Assert.checkNotNullParam("other", other);
            if (other == NONE) {
                return this;
            } else if (other instanceof One) {
                return withCredential(((One) other).credential);
            } else if (other instanceof Two) {
                final Two otherTwo = (Two) other;
                return withCredential(otherTwo.credential1).withCredential(otherTwo.credential2);
            } else if (other instanceof Many) {
                Many otherMany = (Many) other;
                if (otherMany.containsMatching(credential1)) {
                    if (otherMany.containsMatching(credential2)) {
                        return otherMany;
                    } else {
                        return new Many(credential2, otherMany);
                    }
                } else if (otherMany.containsMatching(credential2)) {
                    return new Many(credential1, otherMany);
                } else {
                    return new Many(credential1, credential2, otherMany);
                }
            } else {
                throw Assert.unreachableCode();
            }
        }

        public CredentialSource with(final CredentialSource other) {
            Assert.checkNotNullParam("other", other);
            if (other instanceof IdentityCredentials) {
                return with((IdentityCredentials) other);
            } else {
                return super.with(other);
            }
        }

        public Iterator<Credential> iterator() {
            return EnumerationIterator.over(credential1);
        }

        public <C extends Credential, R> R applyToCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec, final Function<C, R> function) {
            Assert.checkNotNullParam("credentialType", credentialType);
            return credential1.castAndApply(credentialType, algorithmName, parameterSpec, function);
        }

        public IdentityCredentials withoutMatching(final Credential credential) {
            Assert.checkNotNullParam("credential", credential);
            return this.credential1.matches(credential) ? NONE : this;
        }

        public IdentityCredentials without(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
            Assert.checkNotNullParam("credentialType", credentialType);
            return credential1.matches(credentialType, algorithmName, parameterSpec) ? NONE : this;
        }

        public IdentityCredentials without(final Predicate<? super Credential> predicate) {
            Assert.checkNotNullParam("predicate", predicate);
            return predicate.test(credential1) ? predicate.test(credential2) ? NONE : new One(credential2) : predicate.test(credential2) ? new One(credential1) : this;
        }

        public void forEach(final Consumer<? super Credential> action) {
            Assert.checkNotNullParam("action", action);
            action.accept(credential1);
            action.accept(credential2);
        }

        public int size() {
            return 2;
        }

        public int hashCode() {
            return typeHash(credential1) ^ typeHash(credential2);
        }

        public boolean equals(final Object obj) {
            if (! (obj instanceof Two)) {
                return false;
            }
            final Two two = (Two) obj;
            return credential1.equals(two.credential1) && credential2.equals(two.credential2) || credential1.equals(two.credential2) && credential2.equals(two.credential1);
        }
    }

    /**
     * A (hopefully) unique hash code for the kind of credential.
     *
     * @param credential the credential
     * @return the type hash
     */
    static int typeHash(Credential credential) {
        int ch = credential.getClass().hashCode();
        if (credential instanceof AlgorithmCredential) {
            final AlgorithmCredential algorithmCredential = (AlgorithmCredential) credential;
            return multiHashOrdered(multiHashOrdered(ch, 42979, Objects.hashCode(algorithmCredential.getAlgorithm())), 62861, Objects.hashCode(algorithmCredential.getParameters()));
        } else {
            return ch;
        }
    }

    static class Many extends IdentityCredentials {
        private final LinkedHashMap<Key, Credential> map;
        private final int hashCode;

        Many(final Credential c1, final Many subsequent) {
            LinkedHashMap<Key, Credential> map = new LinkedHashMap<>(subsequent.map.size() + 1);
            map.put(Key.of(c1), c1);
            map.putAll(subsequent.map);
            this.map = map;
            int hc = 0;
            for (Credential credential : map.values()) {
                hc ^= typeHash(credential);
            }
            hashCode = hc;
            assert size() > 2;
        }

        Many(final Credential c1, final Credential c2, final Many subsequent) {
            LinkedHashMap<Key, Credential> map = new LinkedHashMap<>(subsequent.map.size() + 2);
            map.put(Key.of(c1), c1);
            map.put(Key.of(c2), c2);
            map.putAll(subsequent.map);
            this.map = map;
            int hc = 0;
            for (Credential credential : map.values()) {
                hc ^= typeHash(credential);
            }
            hashCode = hc;
            assert size() > 2;
        }

        Many(final LinkedHashMap<Key, Credential> map) {
            this.map = map;
            int hc = 0;
            for (Credential credential : map.values()) {
                hc ^= typeHash(credential);
            }
            hashCode = hc;
            assert size() > 2;
        }

        Many(final Credential credential1, final Credential credential2, final Credential credential3) {
            LinkedHashMap<Key, Credential> map = new LinkedHashMap<>(3);
            map.put(Key.of(credential1), credential1);
            map.put(Key.of(credential2), credential2);
            map.put(Key.of(credential3), credential3);
            this.map = map;
            int hc = 0;
            for (Credential credential : map.values()) {
                hc ^= typeHash(credential);
            }
            hashCode = hc;
            assert size() > 2;
        }

        public boolean contains(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
            return map.containsKey(new Key(credentialType, algorithmName, parameterSpec));
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
            return credentialType.cast(map.get(new Key(credentialType, algorithmName, parameterSpec)).clone());
        }

        public IdentityCredentials withoutMatching(final Credential credential) {
            final Key key = Key.of(credential);
            if (map.containsKey(key)) {
                final LinkedHashMap<Key, Credential> clone = new LinkedHashMap<>(map);
                clone.remove(key);
                if (clone.size() == 2) {
                    final Iterator<Credential> iterator = clone.values().iterator();
                    return new Two(iterator.next(), iterator.next());
                } else {
                    return new Many(clone);
                }
            } else {
                return this;
            }
        }

        public void forEach(final Consumer<? super Credential> action) {
            map.values().forEach(action);
        }

        public int size() {
            return map.size();
        }

        public IdentityCredentials withCredential(final Credential credential) {
            final LinkedHashMap<Key, Credential> clone = new LinkedHashMap<>(map);
            final Key key = Key.of(credential);
            // do this as two steps so it's added to the end
            clone.remove(key);
            clone.put(key, credential);
            return new Many(clone);
        }

        public IdentityCredentials with(final IdentityCredentials other) {
            final LinkedHashMap<Key, Credential> clone = new LinkedHashMap<>(map);
            for (Credential credential : other) {
                final Key key = Key.of(credential);
                clone.remove(key);
                clone.put(key, credential);
            }
            return new Many(clone);
        }

        public CredentialSource with(final CredentialSource other) {
            return other instanceof IdentityCredentials ? with((IdentityCredentials) other) : super.with(other);
        }

        public Iterator<Credential> iterator() {
            return Collections.unmodifiableCollection(map.values()).iterator();
        }

        public <C extends Credential, R> R applyToCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec, final Function<C, R> function) {
            final Key key = new Key(credentialType, algorithmName, parameterSpec);
            final Credential credential = map.get(key);
            if (credential != null) {
                return function.apply(credentialType.cast(credential));
            }
            return null;
        }

        public IdentityCredentials without(final Predicate<? super Credential> predicate) {
            final LinkedHashMap<Key, Credential> clone = new LinkedHashMap<>(map);
            final Collection<Credential> values = clone.values();
            values.removeIf(predicate);
            final Iterator<Credential> iterator = values.iterator();
            if (iterator.hasNext()) {
                final Credential c1 = iterator.next();
                if (iterator.hasNext()) {
                    final Credential c2 = iterator.next();
                    if (iterator.hasNext()) {
                        return new Many(clone);
                    } else {
                        return new Two(c1, c2);
                    }
                } else {
                    return new One(c1);
                }
            } else {
                return NONE;
            }
        }

        public int hashCode() {
            return hashCode;
        }

        public boolean equals(final Object obj) {
            if (! (obj instanceof Many)) {
                return false;
            }
            Many many = (Many) obj;
            // check is potentially expensive so start here
            if (hashCode != many.hashCode) {
                return false;
            }
            if (map.size() != many.map.size()) {
                return false;
            }
            // now the O(n) part
            for (Map.Entry<Key, Credential> entry : map.entrySet()) {
                if (! Objects.equals(many.map.get(entry.getKey()), entry.getValue())) {
                    return false;
                }
            }
            return true;
        }
    }

    static final class Key {
        private final Class<? extends Credential> clazz;
        private final String algorithm;
        private final AlgorithmParameterSpec parameterSpec;
        private final int hashCode;

        Key(final Class<? extends Credential> clazz, final String algorithm, final AlgorithmParameterSpec parameterSpec) {
            this.clazz = clazz;
            this.algorithm = algorithm;
            this.parameterSpec = parameterSpec;
            hashCode = multiHashOrdered(multiHashOrdered(clazz.hashCode(), 42979, Objects.hashCode(algorithm)), 62861, Objects.hashCode(parameterSpec));
        }

        static Key of(Credential c) {
            if (c instanceof AlgorithmCredential) {
                final AlgorithmCredential ac = (AlgorithmCredential) c;
                return new Key(ac.getClass(), ac.getAlgorithm(), ac.getParameters());
            } else {
                return new Key(c.getClass(), null, null);
            }
        }

        public int hashCode() {
            return hashCode;
        }

        public boolean equals(final Object obj) {
            return obj instanceof Key && equals((Key) obj);
        }

        private boolean equals(final Key key) {
            return clazz == key.clazz && Objects.equals(algorithm, key.algorithm) && Objects.equals(parameterSpec, key.parameterSpec);
        }

        Class<? extends Credential> getClazz() {
            return clazz;
        }

        String getAlgorithm() {
            return algorithm;
        }

        AlgorithmParameterSpec getParameterSpec() {
            return parameterSpec;
        }
    }
}
