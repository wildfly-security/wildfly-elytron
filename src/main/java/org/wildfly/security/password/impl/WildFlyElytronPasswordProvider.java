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

import java.security.Provider;
import java.util.Collections;

@SuppressWarnings("ThisEscapedInObjectConstruction")
public final class WildFlyElytronPasswordProvider extends Provider {

    private static final long serialVersionUID = 2138229726296095412L;

    public WildFlyElytronPasswordProvider() {
        super("WildFlyElytronPassword", 1.0, "WildFly Elytron Password Provider");
        putService(new Service(this, "Password", "clear", PasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
    }
}
