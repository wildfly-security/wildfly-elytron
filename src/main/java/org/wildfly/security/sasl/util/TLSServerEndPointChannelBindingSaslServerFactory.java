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

package org.wildfly.security.sasl.util;

import static org.wildfly.security.sasl.util.TLSServerEndPointChannelBinding.getDigestAlgorithm;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.auth.callback.SSLCallback;

/**
 * A SASL server factory which implements the {@code tls-server-end-point} channel binding algorithm.  The channel
  * binding will not be activated unless this SASL server factory wraps a {@link SSLSaslServerFactory}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class TLSServerEndPointChannelBindingSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate server factory
     */
    public TLSServerEndPointChannelBindingSaslServerFactory(final SaslServerFactory delegate) {
        super(delegate);
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        return super.createSaslServer(mechanism, protocol, serverName, props, new CallbackHandler() {
            private byte[] bindingData;

            public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                ArrayList<Callback> list = new ArrayList<>(Arrays.asList(callbacks));
                final Iterator<Callback> iterator = list.iterator();
                while (iterator.hasNext()) {
                    Callback callback = iterator.next();
                    if (callback instanceof SSLCallback) {
                        final SSLCallback sslCallback = (SSLCallback) callback;
                        final Certificate[] localCertificates = sslCallback.getSslSession().getLocalCertificates();
                        if (localCertificates != null && localCertificates.length > 0) {
                            final X509Certificate localCertificate = (X509Certificate) localCertificates[0];
                            final String sigAlgOID = localCertificate.getSigAlgOID();
                            final String digestAlgorithm = getDigestAlgorithm(sigAlgOID);
                            if (digestAlgorithm != null) try {
                                final MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithm);
                                final byte[] encoded = localCertificate.getEncoded();
                                bindingData = messageDigest.digest(encoded);
                            } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
                                // fail silently
                            }
                        }
                    } else if (callback instanceof ChannelBindingCallback && bindingData != null) {
                        final ChannelBindingCallback bindingCallback = (ChannelBindingCallback) callback;
                        bindingCallback.setBindingType("tls-server-end-point");
                        bindingCallback.setBindingData(bindingData);
                        iterator.remove();
                    }
                }
                if (! list.isEmpty()) {
                    cbh.handle(list.toArray(new Callback[list.size()]));
                }
            }
        });
    }
}
