/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.password.impl;

import static org.wildfly.security.password.interfaces.BCryptPassword.*;
import static org.wildfly.security.password.interfaces.ClearPassword.*;
import static org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword.*;
import static org.wildfly.security.password.interfaces.TrivialDigestPassword.*;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.*;
import static org.wildfly.security.password.interfaces.UnixMD5CryptPassword.*;
import static org.wildfly.security.password.interfaces.UnixDESCryptPassword.*;

import java.security.Provider;
import java.util.Collections;

@SuppressWarnings("ThisEscapedInObjectConstruction")
public final class WildFlyElytronPasswordProvider extends Provider {

    private static final long serialVersionUID = 2138229726296095412L;

    public WildFlyElytronPasswordProvider() {
        super("WildFlyElytronPassword", 1.0, "WildFly Elytron Password Provider");
        putService(new Service(this, "Password", ALGORITHM_CLEAR, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_CRYPT_MD5, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_SUN_CRYPT_MD5, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_SUN_CRYPT_MD5_BARE_SALT, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_CRYPT_SHA_256, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_CRYPT_SHA_512, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_DIGEST_MD2, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_DIGEST_MD5, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_DIGEST_SHA_1, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_DIGEST_SHA_256, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_DIGEST_SHA_384, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_DIGEST_SHA_512, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_CRYPT_DES, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", ALGORITHM_BCRYPT, PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
    }

}
