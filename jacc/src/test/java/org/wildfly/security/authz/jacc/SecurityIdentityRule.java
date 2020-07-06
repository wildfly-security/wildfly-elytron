/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.authz.jacc;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.security.PrivilegedAction;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
// has dependency on wildfly-elytron-realm
public class SecurityIdentityRule implements TestRule {

    private SecurityDomain securityDomain;

    public SecurityIdentityRule(SecurityDomain securityDomain) {
        this.securityDomain = securityDomain;
    }

    @Override
    public Statement apply(Statement base, Description description) {
        RunAs runAs = description.getAnnotation(RunAs.class);

        if (runAs == null) {
            runAs = description.getTestClass().getAnnotation(RunAs.class);
        }

        if (runAs == null) {
            throw new RuntimeException("@RunAs is missing on test method or test class.");
        }

        final SecurityIdentity runAsIdentity = runAs.value().equals("anonymous") ?
                securityDomain.getCurrentSecurityIdentity().createRunAsAnonymous() :
                securityDomain.getCurrentSecurityIdentity().createRunAsIdentity(runAs.value());
        return new RunAsSecurityIdentity(base, runAsIdentity);
    }

    public class RunAsSecurityIdentity extends Statement {

        private final SecurityIdentity authorizedIdentity;
        private final Statement delegate;

        public RunAsSecurityIdentity(Statement delegate, SecurityIdentity authorizedIdentity) {
            this.delegate = delegate;
            this.authorizedIdentity = authorizedIdentity;
        }

        @Override
        public void evaluate() throws Throwable {
            this.authorizedIdentity.runAs((PrivilegedAction<Void>) () -> {
                try {
                    this.delegate.evaluate();
                } catch (Throwable cause) {
                    throw new RuntimeException("Error while evaluating test method.", cause);
                }

                return null;
            });
        }
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE, ElementType.METHOD})
    public @interface RunAs {
        String value();
    }
}
