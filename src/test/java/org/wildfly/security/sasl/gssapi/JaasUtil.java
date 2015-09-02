/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.sasl.gssapi;

import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jboss.logging.Logger;

/**
 * Utility class for the JAAS based logins.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class JaasUtil {

    private static Logger log = Logger.getLogger(JaasUtil.class);

    private static final boolean IS_IBM = System.getProperty("java.vendor").contains("IBM");

    public static Subject loginClient() throws LoginException {
        log.debug("loginClient");
        return login("jduke", "theduke".toCharArray(), false, null);
    }

    public static Subject loginServer(String keyTabFile) throws LoginException {
        log.debug("loginServer");
        return login("sasl/test_server_1", "servicepwd".toCharArray(), true, keyTabFile);
    }

    static Subject login(final String userName, final char[] password, final boolean server, final String keyTabFile) throws LoginException {
        Subject theSubject = new Subject();
        CallbackHandler cbh = new UsernamePasswordCBH(userName, password);
        Configuration config;
        if (server) {
            config = createGssProxyConfiguration(userName, keyTabFile);
        } else {
            config = createJaasConfiguration(false);
        }
        LoginContext lc = new LoginContext("KDC", theSubject, cbh, config);
        lc.login();

        return theSubject;
    }

    private static Configuration createJaasConfiguration(final boolean server) {
        return new Configuration() {

            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                if ("KDC".equals(name) == false) {
                    throw new IllegalArgumentException(String.format("Unexpected name '%s'", name));
                }

                AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
                Map<String, Object> options = new HashMap<String, Object>();
                options.put("debug", "true");
                options.put("refreshKrb5Config", "true");

                if (IS_IBM) {
                    options.put("noAddress", "true");
                    options.put("credsType", server ? "acceptor" : "initiator");
                    entries[0] = new AppConfigurationEntry("com.ibm.security.auth.module.Krb5LoginModule", REQUIRED, options);
                } else {
                    options.put("storeKey", "true");
                    options.put("isInitiator", server ? "false" : "true");
                    entries[0] = new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", REQUIRED, options);
                }

                return entries;
            }

        };
    }

    private static Configuration createGssProxyConfiguration(final String principal, final String keyTabFile) {
        return new Configuration() {

            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                if ("KDC".equals(name) == false) {
                    throw new IllegalArgumentException(String.format("Unexpected name '%s'", name));
                }

                AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
                Map<String, Object> options = new HashMap<String, Object>();
                options.put("debug", "true");
                options.put("refreshKrb5Config", "true");
                options.put("useKeyTab", "true");
                options.put("keyTab", keyTabFile);
                options.put("doNotPrompt", "true");
                options.put("principal", principal);

                if (IS_IBM) {
                    options.put("noAddress", "true");
                    options.put("credsType", "acceptor");
                    entries[0] = new AppConfigurationEntry("com.ibm.security.auth.module.Krb5LoginModule", REQUIRED, options);
                } else {
                    options.put("storeKey", "true");
                    options.put("isInitiator", "false");
                    entries[0] = new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", REQUIRED, options);
                }

                return entries;
            }

        };
    }

    private static class UsernamePasswordCBH implements CallbackHandler {

        /*
         * Note: We use CallbackHandler implementations like this in test cases as test cases need to run unattended, a true
         * CallbackHandler implementation should interact directly with the current user to prompt for the username and
         * password.
         *
         * i.e. In a client app NEVER prompt for these values in advance and provide them to a CallbackHandler like this.
         */

        private final String username;
        private final char[] password;

        private UsernamePasswordCBH(final String username, final char[] password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback current : callbacks) {
                if (current instanceof NameCallback) {
                    NameCallback ncb = (NameCallback) current;
                    ncb.setName(username);
                } else if (current instanceof PasswordCallback) {
                    PasswordCallback pcb = (PasswordCallback) current;
                    pcb.setPassword(password);
                } else {
                    throw new UnsupportedCallbackException(current);
                }
            }

        }

    }

}
