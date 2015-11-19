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
 * A credential which contains an X.509 certificate chain.
 */
public interface X509CertificateChainCredential extends AlgorithmCredential {

    /**
     * Get a copy of the certificate chain.
     *
     * @return a copy of the certificate chain
     */
    X509Certificate[] getCertificateChain();

    /**
     * Get the first certificate in the chain.  This corresponds to the subject certificate.
     *
     * @return the first certificate (not {@code null})
     */
    X509Certificate getFirstCertificate();

    /**
     * Get the last certificate in the chain.  This corresponds to the ultimate issuer certificate.
     *
     * @return the last certificate (not {@code null})
     */
    X509Certificate getLastCertificate();
}
