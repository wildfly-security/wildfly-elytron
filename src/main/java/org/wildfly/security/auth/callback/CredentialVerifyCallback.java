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
package org.wildfly.security.auth.callback;

/**
 * A {@link Callback} for use where credential verification is required.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class CredentialVerifyCallback implements ExtendedCallback {

    private final Object credential;
    private boolean verified;

    /**
     * Construct a new instance of this {@link Callback}.
     *
     * @param credential the credential to be verified.
     */
    public CredentialVerifyCallback(final Object credential) {
        this.credential = credential;
    }

    /**
     * Get the credential being verified.
     *
     * @return the credential being verified.
     */
    public Object getCredential() {
        return credential;
    }

    /**
     * Set if the credential referenced here has been verified.
     *
     * @param verified the verification state of the credential.
     */
    public void setVerified(final boolean verified) {
        this.verified = verified;
    }

    /**
     * Get the verification state for the credential referenced here.
     *
     * @return {@code true} if the credential has been verified, {@code false} otherwise.
     */
    public boolean isVerified() {
        return verified;
    }

    /**
     * This {@link Callback} is not optional as verification is required.
     */
    @Override
    public boolean isOptional() {
        return false;
    }

    /**
     * This {@link Callback} needs to know if credential validation was successful.
     */
    @Override
    public boolean needsInformation() {
        return true;
    }

}
