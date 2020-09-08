/*
 * Copyright 2020 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.authz.jacc;

import static org.wildfly.security.authz.jacc.SecurityActions.doPrivileged;
import static org.wildfly.security.authz.jacc.SubjectUtil.fromSecurityIdentity;

import java.security.PrivilegedAction;

import javax.security.jacc.PolicyContextException;
import javax.security.jacc.PolicyContextHandler;

import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * A {@code PolicyContextHandler} to return a {@code Subject} from the current {@code SecurityIdentity}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SubjectPolicyContextHandler implements PolicyContextHandler {

    private static final String KEY = "javax.security.auth.Subject.container";

    @Override
    public boolean supports(String key) throws PolicyContextException {
        return KEY.equalsIgnoreCase(key);
    }

    @Override
    public String[] getKeys() throws PolicyContextException {
        return new String[] { KEY };
    }

    @Override
    public Object getContext(String key, Object data) throws PolicyContextException {
        if (!supports(key)) {
            return null;
        }

        SecurityIdentity securityIdentity = getSecurityIdentity();
        if (securityIdentity != null) {
            return fromSecurityIdentity(securityIdentity);
        }

        return null;
    }

    private static SecurityIdentity getSecurityIdentity() {
        SecurityDomain securityDomain = doPrivileged((PrivilegedAction<SecurityDomain>) SecurityDomain::getCurrent);

        if (securityDomain != null) {
            return securityDomain.getCurrentSecurityIdentity();
        }

        return null;
    }
}
