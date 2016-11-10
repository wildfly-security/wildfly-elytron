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

import java.util.Collections;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.Function;
import java.util.function.Predicate;

import org.wildfly.common.Assert;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;

/**
 * The public or private credentials retained by an identity, which can be used for authentication forwarding.  This
 * credentials set can contain zero or one credential of a given type and algorithm name.  If the credential type
 * does not support algorithm names, then the set can contain zero or one credential of that type.  The credential
 * set may be iterated; iteration order is not prescribed and may change if the implementation is changed.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class IdentityCredentials implements Iterable<Credential> {
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

    /**
     * Determine whether a credential of the given type and algorithm are present in this set.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type
     * does not support algorithm names
     * @return {@code true} if a matching credential is contained in this set, {@code false} otherwise
     */
    public abstract boolean contains(Class<? extends Credential> credentialType, String algorithmName);

    /**
     * Determine whether a credential of the type and algorithm of the given credential is present in this set.
     *
     * @param credential the credential to check against (must not be {@code null})
     * @return {@code true} if a matching credential is contained in this set, {@code false} otherwise
     */
    public final boolean containsMatching(Credential credential) {
        Assert.checkNotNullParam("credential", credential);
        return credential instanceof AlgorithmCredential ? contains(credential.getClass(), ((AlgorithmCredential) credential).getAlgorithm()) : contains(credential.getClass());
    }

    /**
     * Acquire a credential of the given type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param <C> the credential type
     * @return the credential, or {@code null} if no such credential exists
     */
    public final <C extends Credential> C getCredential(Class<C> credentialType) {
        return getCredential(credentialType, null);
    }

    /**
     * Acquire a credential of the given type and algorithm name.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type
     * does not support algorithm names
     * @param <C> the credential type
     *
     * @return the credential, or {@code null} if no such credential exists
     */
    public abstract <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName);

    /**
     * Apply the given function to the acquired credential, if it is set and of the given type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param function the function to apply (must not be {@code null})
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the criteria are not met
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    public final <C extends Credential, R> R applyToCredential(Class<C> credentialType, Function<C, R> function) throws RealmUnavailableException {
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
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    public final <C extends Credential, R> R applyToCredential(Class<C> credentialType, String algorithmName, Function<C, R> function) throws RealmUnavailableException {
        final Credential credential = getCredential(credentialType, algorithmName);
        return credential == null ? null : credential.castAndApply(credentialType, algorithmName, function);
    }

    /**
     * Return a copy of this credential set, but with the given credential added to it.
     *
     * @param credential the credential to append (must not be {@code null})
     * @return the new credential set (not {@code null})
     */
    public final IdentityCredentials withCredential(Credential credential) {
        return new CredentialNode(withoutMatching(credential), credential);
    }

    /**
     * Return a copy of this credential set with the given credential set added to it.
     *
     * @param other the credential set to append (must not be {@code null})
     * @return the new credential set (not {@code null})
     */
    public abstract IdentityCredentials with(IdentityCredentials other);

    /**
     * Return a copy of this credential set without any credentials of the given type.  If the credential type is not
     * found in this set, return this instance.
     *
     * @param credentialType the credential type to remove (must not be {@code null})
     * @return the new credential set (not {@code null})
     */
    public IdentityCredentials without(Class<? extends Credential> credentialType) {
        Assert.checkNotNullParam("credentialType", credentialType);
        return without(credentialType::isInstance);
    }

    /**
     * Return a copy of this credential set without any credentials with a type and algorithm name matching that of the
     * given credential.  If the credential type and algorithm name is not found in this set, return this instance.
     *
     * @param credential the credential to match against (must not be {@code null})
     * @return the new credential set (not {@code null})
     */
    public IdentityCredentials withoutMatching(Credential credential) {
        Assert.checkNotNullParam("credential", credential);
        return without(credential::matches);
    }

    /**
     * Return a copy of this credential set without any credentials of the given type and algorithm name.  If the
     * credential type and algorithm name is not found in this set, return this instance.
     *
     * @param credentialType the credential type to remove (must not be {@code null})
     * @param algorithmName the algorithm name to remove, or {@code null} to match any algorithm name
     * @return the new credential set (not {@code null})
     */
    public IdentityCredentials without(final Class<? extends Credential> credentialType, final String algorithmName) {
        if (algorithmName == null) {
            return without(credentialType);
        } else if (AlgorithmCredential.class.isAssignableFrom(credentialType)) {
            return without(cred -> credentialType.isInstance(cred) && algorithmName.equals(((AlgorithmCredential) cred).getAlgorithm()));
        } else {
            // impossible to have a credential with an algorithm that isn't an AlgorithmCredential
            return this;
        }
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
     * Iterate over this identity credential set.
     *
     * @return the iterator (not {@code null})
     */
    public Iterator<Credential> iterator() {
        return new Itr(this);
    }

    /**
     * Get a {@link Spliterator} for this credential set.
     *
     * @return the spliterator (not {@code null})
     */
    public Spliterator<Credential> spliterator() {
        return Spliterators.spliterator(iterator(), size(), Spliterator.IMMUTABLE | Spliterator.DISTINCT | Spliterator.NONNULL | Spliterator.ORDERED);
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
        IdentityCredentials getNext() {
            return null;
        }

        public boolean contains(final Class<? extends Credential> credentialType, final String algorithmName) {
            return false;
        }

        public IdentityCredentials without(final Predicate<? super Credential> predicate) {
            return this;
        }

        Credential getCredential() {
            return null;
        }

        public IdentityCredentials without(final Class<? extends Credential> credentialType) {
            return this;
        }

        public IdentityCredentials withoutMatching(final Credential credential) {
            return this;
        }

        public IdentityCredentials without(final Class<? extends Credential> credentialType, final String algorithmName) {
            return this;
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) {
            return null;
        }

        public IdentityCredentials with(final IdentityCredentials other) {
            return other;
        }

        public Iterator<Credential> iterator() {
            return Collections.emptyIterator();
        }

        public Spliterator<Credential> spliterator() {
            return Spliterators.emptySpliterator();
        }

        public int size() {
            return 0;
        }
    };

    // Linked list specification, used for iterator

    abstract IdentityCredentials getNext();

    abstract Credential getCredential();

    // Iterator implementation

    static class Itr implements Iterator<Credential> {
        private IdentityCredentials current;

        Itr(final IdentityCredentials current) {
            this.current = current;
        }

        public boolean hasNext() {
            return current != NONE;
        }

        public Credential next() {
            IdentityCredentials current = this.current;
            if (current == NONE) {
                throw new NoSuchElementException();
            } else try {
                return current.getCredential();
            } finally {
                this.current = current.getNext();
            }
        }
    }

    static class CredentialNode extends IdentityCredentials {
        private final IdentityCredentials next;
        private final Credential credential;
        private final int size;

        CredentialNode(final IdentityCredentials next, final Credential credential) {
            this.next = next;
            this.credential = credential;
            size = next.size() + 1;
        }

        private CredentialNode withNext(IdentityCredentials next) {
            if (next == this.next) {
                return this;
            } else {
                return new CredentialNode(next, credential);
            }
        }

        IdentityCredentials getNext() {
            return next;
        }

        Credential getCredential() {
            return credential;
        }

        public int size() {
            return size;
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) {
            Assert.checkNotNullParam("credentialType", credentialType);
            final Credential credential = this.credential;
            if (credential instanceof AlgorithmCredential) {
                AlgorithmCredential algorithmCredential = (AlgorithmCredential) credential;
                if (credentialType.isInstance(algorithmCredential) && (algorithmName == null || algorithmName.equals(algorithmCredential.getAlgorithm()))) {
                    return credentialType.cast(algorithmCredential);
                } else {
                    return next.getCredential(credentialType, algorithmName);
                }
            } else {
                if (algorithmName == null && credentialType.isInstance(credential)) {
                    return credentialType.cast(credential);
                } else {
                    return next.getCredential(credentialType, algorithmName);
                }
            }
        }

        public boolean contains(final Class<? extends Credential> credentialType, final String algorithmName) {
            Assert.checkNotNullParam("credentialType", credentialType);
            Credential credential = this.credential;
            if (credential instanceof AlgorithmCredential) {
                return credentialType.isInstance(credential) && algorithmName.equals(((AlgorithmCredential) credential).getAlgorithm());
            } else {
                return algorithmName == null && credentialType.isInstance(credential);
            }
        }

        public IdentityCredentials without(final Predicate<? super Credential> predicate) {
            Assert.checkNotNullParam("predicate", predicate);
            if (predicate.test(credential)) {
                return next.without(predicate);
            } else {
                return withNext(next.without(predicate));
            }
        }

        public IdentityCredentials with(final IdentityCredentials other) {
            if (other == NONE) return this;
            return withNext(without(cred -> cred instanceof AlgorithmCredential ? other.getCredential(cred.getClass(), ((AlgorithmCredential) cred).getAlgorithm()) != null : other.getCredential(cred.getClass()) != null));
        }
    }
}
