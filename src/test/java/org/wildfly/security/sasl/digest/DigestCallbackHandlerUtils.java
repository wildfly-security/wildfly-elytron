/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import java.net.URI;
import java.security.spec.KeySpec;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.DigestPasswordSpec;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.sasl.util.UsernamePasswordHashUtil;

/**
 * @author Kabir Khan
 */
public class DigestCallbackHandlerUtils {

    static CallbackHandler createClearPwdClientCallbackHandler(final String username, final String password, final String sentRealm) throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        return createClientCallbackHandler(username, passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray())), sentRealm);
    }

    static CallbackHandler createDigestPwdClientCallbackHandler(final String username, final String password, final String realm, final String sentRealm) throws Exception {
        byte[] urpHash = new UsernamePasswordHashUtil().generateHashedURP(username, realm, password.toCharArray());
        KeySpec keySpec = new DigestPasswordSpec(username, realm, urpHash);
        PasswordFactory passwordFactory = PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_MD5);
        return createClientCallbackHandler(username, passwordFactory.generatePassword(keySpec), sentRealm);
    }

    private static CallbackHandler createClientCallbackHandler(final String username, final Password password, final String sentRealm) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.empty()
                                .useName(username)
                                .usePassword(password)
                                .useRealm(sentRealm)
                                .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism(SaslMechanismInformation.Names.DIGEST_MD5)));


        return ClientUtils.getCallbackHandler(new URI("seems://irrelevant"), context);
    }
}
