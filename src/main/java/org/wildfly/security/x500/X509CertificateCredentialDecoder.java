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

package org.wildfly.security.x500;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.auth.spi.CredentialDecoder;

/**
 * A credential decoder which can decode an {@link X509Certificate}.  The decoded name is the subject DN as a
 * string in {@link X500Principal#CANONICAL} format.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X509CertificateCredentialDecoder implements CredentialDecoder {

    /**
     * Construct a new instance.
     */
    public X509CertificateCredentialDecoder() {
    }

    public String getNameFromCredential(final Object credential) {
        if (credential instanceof X509Certificate) {
            return ((X509Certificate) credential).getSubjectX500Principal().getName(X500Principal.CANONICAL);
        }
        return null;
    }
}
