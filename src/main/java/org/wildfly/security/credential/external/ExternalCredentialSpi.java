/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.credential.external;

import java.util.Map;
import java.util.Set;

import org.wildfly.security.credential.Credential;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public abstract class ExternalCredentialSpi {

    /**
     * Resolve credential from external source using specified parameters.
     * @param parameters to obtain external password
     * @param credentialType type of {@link Credential} to get back form this method
     * @param <C> type parameter of {@link Credential}
     * @return {@link Credential} from service provider
     * @throws ExternalCredentialException if anything goes wrong while resolving the credential
     */
    public abstract <C extends Credential> C resolveCredential(Map<String, String> parameters, Class<C> credentialType)
            throws ExternalCredentialException;

    /**
     * Resolve credential from external source using password command.
     * @param passwordCommand to obtain external password
     * @param credentialType type of {@link Credential} to get back form this method
     * @param <C> type parameter of {@link Credential}
     * @return {@link Credential} from service provider
     * @throws ExternalCredentialException if anything goes wrong while resolving the credential
     */
    public abstract <C extends Credential> C resolveCredential(String passwordCommand, Class<C> credentialType)
            throws ExternalCredentialException;

    /**
     * This method provides parameters supported by external credential provider. The {@code Set} can be used
     * to filter parameters supplied {@link #resolveCredential(Map, Class)} or {@link #resolveCredential(String, Class)}
     * methods.
     *
     * @return {@code Set<String>} of supported parameters
     */
    public abstract Set<String> supportedParameters();
}
