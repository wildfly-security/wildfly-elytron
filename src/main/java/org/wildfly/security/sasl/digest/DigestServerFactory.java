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

package org.wildfly.security.sasl.digest;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.AbstractSaslFactory;
import org.wildfly.security.sasl.util.Charsets;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
@MetaInfServices(value = SaslServerFactory.class)
public class DigestServerFactory extends AbstractSaslFactory implements SaslServerFactory {

    public static final char REALM_DELIMITER = ' ';
    public static final char REALM_ESCAPE_CHARACTER = '\\';

    public DigestServerFactory() {
        super(Digest.DIGEST_MD5);
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

        String realmList = (String)props.get(WildFlySasl.REALM_LIST);
        String[] realms;
        if (realmList != null) {
            realms = realmsPropertyToArray(realmList);
        } else {
            realms = new String[] {serverName};
        }

        Boolean utf8 = (Boolean)props.get(WildFlySasl.USE_UTF8);
        Charset charset = (utf8==null || utf8.booleanValue()) ? Charsets.UTF_8 : Charsets.LATIN_1;

        String qopsString = (String)props.get(Sasl.QOP);
        String[] qops = qopsString==null ? null : qopsString.split(",");

        String supportedCipherOpts = (String)props.get(WildFlySasl.SUPPORTED_CIPHER_NAMES);
        String[] cipherOpts = (supportedCipherOpts == null ? null : supportedCipherOpts.split(","));

        final DigestSaslServer server = new DigestSaslServer(realms, mechanism, protocol, serverName, cbh, charset, qops, cipherOpts);
        server.init();
        return server;
    }

    /**
     * Helper for getting value of REALM_PROPERTY from array of realms
     */
    public static String realmsArrayToProperty(String[] array){
        StringBuilder realms = new StringBuilder();
        for(int j=0; j<array.length; j++){
            if(j != 0) realms.append(REALM_DELIMITER);
            for(int i=0; i<array[j].length(); i++){
                switch(array[j].charAt(i)){
                    case REALM_ESCAPE_CHARACTER:
                        realms.append(REALM_ESCAPE_CHARACTER);
                        realms.append(REALM_ESCAPE_CHARACTER);
                        break;
                    case REALM_DELIMITER:
                        realms.append(REALM_ESCAPE_CHARACTER);
                        realms.append(REALM_DELIMITER);
                        break;
                    default:
                        realms.append(array[j].charAt(i));
                }
            }
        }
        return realms.toString();
    }

    static String[] realmsPropertyToArray(String property){
        ArrayList<String> array = new ArrayList<String>();
        StringBuilder realm = new StringBuilder();
        boolean wasSlash = false;
        for(int i=0; i<property.length(); i++){
            char c = property.charAt(i);
            if(wasSlash){
                realm.append(property.charAt(i));
                wasSlash = false;
            }else if(c==REALM_ESCAPE_CHARACTER){
                wasSlash = true;
            }else if(c==REALM_DELIMITER){
                array.add(realm.toString());
                realm = new StringBuilder();
            }else{
                realm.append(property.charAt(i));
            }
        }
        array.add(realm.toString());
        return array.toArray(new String[array.size()]);
    }

}
