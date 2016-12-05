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

package org.wildfly.security.credential;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;
import java.util.function.Supplier;

import org.wildfly.common.Assert;
import org.wildfly.security.evidence.AlgorithmEvidence;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.keystore.PasswordEntry;
import org.wildfly.security.x500.X500;

/**
 * A credential is a piece of information that can be used to verify or produce evidence.
 */
public interface Credential extends Cloneable {

    /**
     * An array with no credentials.
     */
    Credential[] NO_CREDENTIALS = new Credential[0];

    /**
     * Determine whether this credential can, generally speaking, verify the given evidence type.
     *
     * @param evidenceClass the evidence type (must not be {@code null})
     * @param algorithmName the evidence algorithm name (may be {@code null} if the type of evidence does not support
     * algorithm names)
     *
     * @return {@code true} if the evidence can be verified by this credential, {@code false} otherwise
     */
    default boolean canVerify(Class<? extends Evidence> evidenceClass, String algorithmName) {
        Assert.checkNotNullParam("evidenceClass", evidenceClass);
        return false;
    }

    /**
     * Determine whether this credential can verify the given evidence.
     *
     * @param evidence the evidence (must not be {@code null})
     *
     * @return {@code true} if the evidence can be verified by this credential, {@code false} otherwise
     */
    default boolean canVerify(Evidence evidence) {
        Assert.checkNotNullParam("evidence", evidence);
        return canVerify(evidence.getClass(), evidence instanceof AlgorithmEvidence ? ((AlgorithmEvidence) evidence).getAlgorithm() : null);
    }

    /**
     * Verify the given evidence.
     *
     * @param evidence the evidence to verify (must not be {@code null})
     *
     * @return {@code true} if the evidence is verified, {@code false} otherwise
     */
    default boolean verify(Evidence evidence) {
        return verify(Security::getProviders, evidence);
    }

    /**
     * Verify the given evidence.
     *
     * @param providerSupplier the provider supplier to use for verification purposes
     * @param evidence the evidence to verify (must not be {@code null})
     *
     * @return {@code true} if the evidence is verified, {@code false} otherwise
     */
    default boolean verify(Supplier<Provider[]> providerSupplier, Evidence evidence) {
        Assert.checkNotNullParam("providerSupplier", providerSupplier);
        Assert.checkNotNullParam("evidence", evidence);
        return false;
    }

    /**
     * Cast this credential type if the type, algorithm, and parameters match.
     *
     * @param credentialType the credential type class to check
     * @param algorithmName the name of the algorithm or {@code null} if any algorithm is acceptable
     * @param parameterSpec the parameter specification or {@code null} if any parameter specification is acceptable
     * @param <C> the credential type
     * @return the credential cast as the target type, or {@code null} if the credential does not match the criteria
     */
    default <C extends Credential> C castAs(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
        return castAndApply(credentialType, algorithmName, parameterSpec, Function.identity());
    }

    /**
     * Cast this credential type if the type and algorithm matches.
     *
     * @param credentialType the credential type class to check
     * @param algorithmName the name of the algorithm or {@code null} if any algorithm is acceptable
     * @param <C> the credential type
     * @return the credential cast as the target type, or {@code null} if the credential does not match the criteria
     */
    default <C extends Credential> C castAs(Class<C> credentialType, String algorithmName) {
        return castAndApply(credentialType, algorithmName, Function.identity());
    }

    /**
     * Cast this credential type if the type matches.
     *
     * @param credentialType the credential type class to check
     * @param <C> the credential type
     * @return the credential cast as the target type, or {@code null} if the credential does not match the criteria
     */
    default <C extends Credential> C castAs(Class<C> credentialType) {
        return castAndApply(credentialType, Function.identity());
    }

    /**
     * Cast this credential type and apply a function if the type matches.
     *
     * @param credentialType the credential type class to check
     * @param algorithmName the name of the algorithm or {@code null} if any algorithm is acceptable
     * @param parameterSpec the parameter specification or {@code null} if any parameter specification is acceptable
     * @param function the function to apply
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the credential is not of the given type
     */
    default <C extends Credential, R> R castAndApply(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec, Function<C, R> function) {
        return credentialType.isInstance(this) && algorithmName == null && parameterSpec == null ? function.apply(credentialType.cast(this)) : null;
    }

    /**
     * Cast this credential type and apply a function if the type matches.
     *
     * @param credentialType the credential type class to check
     * @param algorithmName the name of the algorithm or {@code null} if any algorithm is acceptable
     * @param function the function to apply
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the credential is not of the given type
     */
    default <C extends Credential, R> R castAndApply(Class<C> credentialType, String algorithmName, Function<C, R> function) {
        return credentialType.isInstance(this) && algorithmName == null ? function.apply(credentialType.cast(this)) : null;
    }

    /**
     * Cast this credential type and apply a function if the type matches.
     *
     * @param credentialType the credential type class to check
     * @param function the function to apply
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the credential is not of the given type
     */
    default <C extends Credential, R> R castAndApply(Class<C> credentialType, Function<C, R> function) {
        return credentialType.isInstance(this) ? function.apply(credentialType.cast(this)) : null;
    }

    /**
     * Creates and returns a copy of this {@link Credential}.
     *
     * @return a copy of this {@link Credential}.
     */
    Credential clone();

    /**
     * Determine if this credential is the same kind of credential as the given credential.
     *
     * @param other the other credential
     * @return {@code true} if the credentials are of the same kind, {@code false} otherwise
     */
    default boolean matches(Credential other) {
        return other instanceof AlgorithmCredential ? matches((AlgorithmCredential) other) : other != null && getClass() == other.getClass();
    }

    /**
     * Determine if this credential is the same kind of credential as the given credential.
     *
     * @param other the other credential
     * @return {@code true} if the credentials are of the same kind, {@code false} otherwise
     */
    default boolean matches(AlgorithmCredential other) {
        return false;
    }

    /**
     * Convert a key store entry into a credential object.
     *
     * @param keyStoreEntry the key store entry to convert (must not be {@code null})
     * @return the corresponding credential, or {@code null} if the entry type is unrecognized
     */
    static Credential fromKeyStoreEntry(KeyStore.Entry keyStoreEntry) {
        Assert.checkNotNullParam("keyStoreEntry", keyStoreEntry);
        if (keyStoreEntry instanceof PasswordEntry) {
            return new PasswordCredential(((PasswordEntry) keyStoreEntry).getPassword());
        } else if (keyStoreEntry instanceof KeyStore.PrivateKeyEntry) {
            return new X509CertificateChainPrivateCredential(((KeyStore.PrivateKeyEntry) keyStoreEntry).getPrivateKey(), X500.asX509CertificateArray(((KeyStore.PrivateKeyEntry) keyStoreEntry).getCertificateChain()));
        } else if (keyStoreEntry instanceof KeyStore.TrustedCertificateEntry) {
            return new X509CertificateChainPublicCredential((X509Certificate) ((KeyStore.TrustedCertificateEntry) keyStoreEntry).getTrustedCertificate());
        } else if (keyStoreEntry instanceof KeyStore.SecretKeyEntry) {
            return new SecretKeyCredential(((KeyStore.SecretKeyEntry) keyStoreEntry).getSecretKey());
        } else {
            return null;
        }
    }
}
