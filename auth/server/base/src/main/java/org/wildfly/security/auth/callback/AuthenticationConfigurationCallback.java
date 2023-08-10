/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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
 * A {@link javax.security.auth.callback.Callback} to inform a server authentication context of configured mechanism properties.
 *
 * As an informational {@code Callback} it is optional for the {@code CallbackHandler} to handle this.
 *
 */
public class AuthenticationConfigurationCallback implements ExtendedCallback{

    /**
     * Property of the SASL EXTERNAL mechanism that indicates whether a certificate should be verified against the security realm.
     */
    private boolean saslSkipCertificateVerification;

    public boolean getSaslSkipCertificateVerification() {
        return this.saslSkipCertificateVerification;
    }

    public void setSaslSkipCertificateVerification(boolean skipCertificateVerification) {
        this.saslSkipCertificateVerification = skipCertificateVerification;
    }
}
