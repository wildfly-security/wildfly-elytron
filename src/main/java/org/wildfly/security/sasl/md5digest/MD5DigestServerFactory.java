/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.md5digest;

import java.nio.charset.Charset;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.security.sasl.SaslException;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.sasl.md5digest.MD5DigestSaslServer;
import org.wildfly.security.sasl.util.AbstractSaslFactory;
import org.wildfly.security.sasl.util.Charsets;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
@MetaInfServices(value = SaslServerFactory.class)
public class MD5DigestServerFactory extends AbstractSaslFactory implements SaslServerFactory {

    public static final String JBOSS_DIGEST_MD5 = "DIGEST-MD5";
    public static final String REALM_DELIMITER = " ";

    public MD5DigestServerFactory() {
        super(MD5DigestServerFactory.JBOSS_DIGEST_MD5);
    }

    /* (non-Javadoc)
     * @see javax.security.sasl.SaslServerFactory#createSaslServer(java.lang.String, java.lang.String, java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props,
            CallbackHandler cbh) throws SaslException {
        if (! isIncluded(mechanism)) {
            return null;
        }

        String realmList = (String)props.get(AbstractMD5DigestMechanism.REALM_PROPERTY);
        String[] realms;
        if (realmList != null) {
            realms = realmList.split(REALM_DELIMITER);
        } else {
            realms = new String[] {serverName};
        }

        Boolean utf8 = (Boolean)props.get(AbstractMD5DigestMechanism.UTF8_PROPERTY);
        Charset charset = (utf8==null || utf8.booleanValue()) ? Charsets.UTF_8 : Charsets.LATIN_1;
        
        String qopsString = (String)props.get(AbstractMD5DigestMechanism.QOP_PROPERTY);
        String[] qops = qopsString==null ? null : qopsString.split(",");

        String supportedCipherOpts = (String)props.get(AbstractMD5DigestMechanism.SUPPORTED_CIPHERS_PROPERTY);
        String[] cipherOpts = (supportedCipherOpts == null ? null : supportedCipherOpts.split(","));
        
        final MD5DigestSaslServer server = new MD5DigestSaslServer(realms, mechanism, protocol, serverName, cbh, charset, qops, cipherOpts);
        server.init();
        return server;
    }

}
