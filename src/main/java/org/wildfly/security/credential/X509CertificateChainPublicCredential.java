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

import java.security.cert.X509Certificate;

/**
 * A credential containing an X.509 certificate chain.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X509CertificateChainPublicCredential extends AbstractX509CertificateChainCredential {

    /**
     * Construct a new instance.
     *
     * @param certificateChain the certificate chain (not {@code null}, cannot contain {@code null} elements)
     */
    public X509CertificateChainPublicCredential(final X509Certificate... certificateChain) {
        super(certificateChain);
    }
}
