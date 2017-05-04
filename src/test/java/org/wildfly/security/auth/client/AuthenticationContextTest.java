/*
 * Copyright 2017 JBoss by Red Hat.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.auth.client;

import static org.junit.Assert.*;
import java.security.GeneralSecurityException;
import javax.net.ssl.SSLContext;
import org.junit.Ignore;

import org.junit.Test;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.ssl.SSLContextBuilder;

/**
 * @author <a href="mailto:olukas@redhat.com">Ondrej Lukas</a>
 */
public final class AuthenticationContextTest {

    private final AuthenticationConfiguration config1
            = AuthenticationConfiguration.EMPTY.useName("name1").usePort(1111).useProtocol("protocol1").usePassword("password1");
    private final AuthenticationConfiguration config2
            = AuthenticationConfiguration.EMPTY.useName("name2").usePort(2222).useProtocol("protocol2").usePassword("password2");
    private final AuthenticationConfiguration config3
            = AuthenticationConfiguration.EMPTY.useName("name3").usePort(3333).useProtocol("protocol3").usePassword("password3");
    private final AuthenticationConfiguration config4
            = AuthenticationConfiguration.EMPTY.useName("name4").usePort(4444).useProtocol("protocol4").usePassword("password4");

    private final SecurityFactory<SSLContext> ssl1 = new SSLContextBuilder().setSessionTimeout(1).build();
    private final SecurityFactory<SSLContext> ssl2 = new SSLContextBuilder().setSessionTimeout(2).build();
    private final SecurityFactory<SSLContext> ssl3 = new SSLContextBuilder().setSessionTimeout(3).build();
    private final SecurityFactory<SSLContext> ssl4 = new SSLContextBuilder().setSessionTimeout(4).build();

    @Test
    public void addRuleConfigurationToEmptyCtx() {
        AuthenticationContext ctx = AuthenticationContext.empty().with(MatchRule.ALL.matchHost("someHost"), config1);

        assertExpectedRuleNode(ctx.authRules, config1, MatchRule.ALL.matchHost("someHost"));

        assertNull(ctx.authRules.getNext());
    }

    @Test
    public void addRuleConfigurationAtTheEnd() {
        RuleNode<AuthenticationConfiguration> initialRule = new RuleNode<>(null, MatchRule.ALL.matchPort(1234), config1);
        AuthenticationContext ctx = new AuthenticationContext(initialRule, null)
                .with(MatchRule.ALL.matchHost("someHost"), config2);

        assertExpectedRuleNode(ctx.authRules, config1, MatchRule.ALL.matchPort(1234));

        RuleNode<AuthenticationConfiguration> second = ctx.authRules.getNext();
        assertExpectedRuleNode(second, config2, MatchRule.ALL.matchHost("someHost"));

        assertNull(second.getNext());
    }

    @Test
    public void addRuleConfigurationAtTheStart() {
        RuleNode<AuthenticationConfiguration> initialRule = new RuleNode<>(null, MatchRule.ALL.matchPort(1234), config1);
        AuthenticationContext ctx = new AuthenticationContext(initialRule, null)
                .with(0, MatchRule.ALL.matchHost("someHost"), config2);

        assertExpectedRuleNode(ctx.authRules, config2, MatchRule.ALL.matchHost("someHost"));

        RuleNode<AuthenticationConfiguration> second = ctx.authRules.getNext();
        assertExpectedRuleNode(second, config1, MatchRule.ALL.matchPort(1234));

        assertNull(second.getNext());
    }

    @Test
    public void addRuleConfigurationInTheMiddle() {
        RuleNode<AuthenticationConfiguration> initialRule = new RuleNode<>(
                new RuleNode<>(null, MatchRule.ALL.matchPort(2345), config2),
                MatchRule.ALL.matchPort(1234), config1);
        AuthenticationContext ctx = new AuthenticationContext(initialRule, null)
                .with(1, MatchRule.ALL.matchHost("someHost"), config3);

        assertExpectedRuleNode(ctx.authRules, config1, MatchRule.ALL.matchPort(1234));

        RuleNode<AuthenticationConfiguration> second = ctx.authRules.getNext();
        assertExpectedRuleNode(second, config3, MatchRule.ALL.matchHost("someHost"));

        RuleNode<AuthenticationConfiguration> third = second.getNext();
        assertExpectedRuleNode(third, config2, MatchRule.ALL.matchPort(2345));

        assertNull(third.getNext());
    }

    @Test
    public void addRuleSslToEmptyCtx() throws GeneralSecurityException {
        AuthenticationContext ctx = AuthenticationContext.empty()
                .withSsl(MatchRule.ALL.matchHost("someHost"), ssl1);

        assertExpectedRuleNode(ctx.sslRules, ssl1, MatchRule.ALL.matchHost("someHost"));

        assertNull(ctx.sslRules.getNext());
    }

    @Test
    public void addRuleSslAtTheEnd() {
        RuleNode<SecurityFactory<SSLContext>> initialRule = new RuleNode<>(null, MatchRule.ALL.matchPort(1234), ssl1);
        AuthenticationContext ctx = new AuthenticationContext(null, initialRule)
                .withSsl(MatchRule.ALL.matchHost("someHost"), ssl2);

        assertExpectedRuleNode(ctx.sslRules, ssl1, MatchRule.ALL.matchPort(1234));

        RuleNode<SecurityFactory<SSLContext>> second = ctx.sslRules.getNext();
        assertExpectedRuleNode(second, ssl2, MatchRule.ALL.matchHost("someHost"));

        assertNull(second.getNext());
    }

    @Test
    public void addRuleSslAtTheStart() {
        RuleNode<SecurityFactory<SSLContext>> initialRule = new RuleNode<>(null, MatchRule.ALL.matchPort(1234), ssl1);
        AuthenticationContext ctx = new AuthenticationContext(null, initialRule)
                .withSsl(0, MatchRule.ALL.matchHost("someHost"), ssl2);

        assertExpectedRuleNode(ctx.sslRules, ssl2, MatchRule.ALL.matchHost("someHost"));

        RuleNode<SecurityFactory<SSLContext>> second = ctx.sslRules.getNext();
        assertExpectedRuleNode(second, ssl1, MatchRule.ALL.matchPort(1234));

        assertNull(second.getNext());
    }

    @Test
    public void addRuleSslInTheMiddle() {
        RuleNode<SecurityFactory<SSLContext>> initialRule = new RuleNode<>(
                new RuleNode<>(null, MatchRule.ALL.matchPort(2345), ssl2),
                MatchRule.ALL.matchPort(1234), ssl1);
        AuthenticationContext ctx = new AuthenticationContext(null, initialRule)
                .withSsl(1, MatchRule.ALL.matchHost("someHost"), ssl3);

        assertExpectedRuleNode(ctx.sslRules, ssl1, MatchRule.ALL.matchPort(1234));

        RuleNode<SecurityFactory<SSLContext>> second = ctx.sslRules.getNext();
        assertExpectedRuleNode(second, ssl3, MatchRule.ALL.matchHost("someHost"));

        RuleNode<SecurityFactory<SSLContext>> third = second.getNext();
        assertExpectedRuleNode(third, ssl2, MatchRule.ALL.matchPort(2345));

        assertNull(third.getNext());
    }

    @Test
    public void addRuleCtxToEmptyCtx() {
        RuleNode<AuthenticationConfiguration> testedConfigurationRule = new RuleNode<>(null, MatchRule.ALL.matchPort(1234), config1);
        RuleNode<SecurityFactory<SSLContext>> testedSslRule = new RuleNode<>(null, MatchRule.ALL.matchPort(2345), ssl1);
        AuthenticationContext testedCtx = new AuthenticationContext(testedConfigurationRule, testedSslRule);

        AuthenticationContext ctx = AuthenticationContext.empty().with(testedCtx);

        assertExpectedRuleNode(ctx.authRules, config1, MatchRule.ALL.matchPort(1234));

        assertNull(ctx.authRules.getNext());

        assertExpectedRuleNode(ctx.sslRules, ssl1, MatchRule.ALL.matchPort(2345));

        assertNull(ctx.sslRules.getNext());
    }

    @Test
    public void addRuleCtxToEmptyCtx_noConfiguration() {
        RuleNode<SecurityFactory<SSLContext>> testedSslRule = new RuleNode<>(null, MatchRule.ALL.matchPort(2345), ssl1);
        AuthenticationContext testedCtx = new AuthenticationContext(null, testedSslRule);

        AuthenticationContext ctx = AuthenticationContext.empty().with(testedCtx);

        assertNull(ctx.authRules);

        assertExpectedRuleNode(ctx.sslRules, ssl1, MatchRule.ALL.matchPort(2345));

        assertNull(ctx.sslRules.getNext());
    }

    @Test
    public void addRuleCtxToEmptyCtx_noSsl() {
        RuleNode<AuthenticationConfiguration> testedConfigurationRule = new RuleNode<>(null, MatchRule.ALL.matchPort(1234), config1);
        AuthenticationContext testedCtx = new AuthenticationContext(testedConfigurationRule, null);

        AuthenticationContext ctx = AuthenticationContext.empty().with(testedCtx);

        assertExpectedRuleNode(ctx.authRules, config1, MatchRule.ALL.matchPort(1234));

        assertNull(ctx.authRules.getNext());

        assertNull(ctx.sslRules);
    }

    @Test
    public void addRuleCtxAtTheEnd() {
        RuleNode<AuthenticationConfiguration> testedConfigurationRule = new RuleNode<>(null, MatchRule.ALL.matchPort(1234), config2);
        RuleNode<SecurityFactory<SSLContext>> testedSslRule = new RuleNode<>(null, MatchRule.ALL.matchPort(2345), ssl2);
        AuthenticationContext testedCtx = new AuthenticationContext(testedConfigurationRule, testedSslRule);

        RuleNode<AuthenticationConfiguration> initialConfigurationRule = new RuleNode<>(null, MatchRule.ALL.matchHost("someHost1"), config1);
        RuleNode<SecurityFactory<SSLContext>> initialSslRule = new RuleNode<>(null, MatchRule.ALL.matchHost("someHost2"), ssl1);
        AuthenticationContext ctx = new AuthenticationContext(initialConfigurationRule, initialSslRule)
                .with(testedCtx);

        assertExpectedRuleNode(ctx.authRules, config1, MatchRule.ALL.matchHost("someHost1"));

        RuleNode<AuthenticationConfiguration> secondConfiguration = ctx.authRules.getNext();
        assertExpectedRuleNode(secondConfiguration, config2, MatchRule.ALL.matchPort(1234));

        assertNull(secondConfiguration.getNext());

        assertExpectedRuleNode(ctx.sslRules, ssl1, MatchRule.ALL.matchHost("someHost2"));

        RuleNode<SecurityFactory<SSLContext>> secondSsl = ctx.sslRules.getNext();
        assertExpectedRuleNode(secondSsl, ssl2, MatchRule.ALL.matchPort(2345));

        assertNull(secondSsl.getNext());
    }

    @Test
    public void addRuleCtxConfiguration_noInitialSsl() {
        RuleNode<AuthenticationConfiguration> testedConfigurationRule = new RuleNode<>(null, MatchRule.ALL.matchPort(1234), config2);
        RuleNode<SecurityFactory<SSLContext>> testedSslRule = new RuleNode<>(null, MatchRule.ALL.matchHost("someHost2"), ssl1);
        AuthenticationContext testedCtx = new AuthenticationContext(testedConfigurationRule, testedSslRule);

        RuleNode<AuthenticationConfiguration> initialConfigurationRule = new RuleNode<>(null, MatchRule.ALL.matchHost("someHost1"), config1);
        AuthenticationContext ctx = new AuthenticationContext(initialConfigurationRule, null)
                .with(testedCtx);

        assertExpectedRuleNode(ctx.authRules, config1, MatchRule.ALL.matchHost("someHost1"));

        RuleNode<AuthenticationConfiguration> secondConfiguration = ctx.authRules.getNext();
        assertExpectedRuleNode(secondConfiguration, config2, MatchRule.ALL.matchPort(1234));

        assertNull(secondConfiguration.getNext());

        assertExpectedRuleNode(ctx.sslRules, ssl1, MatchRule.ALL.matchHost("someHost2"));

        assertNull(ctx.sslRules.getNext());
    }

    @Test
    public void addRuleCtxConfiguration_noInitialConfig() {
        RuleNode<AuthenticationConfiguration> testedConfigurationRule = new RuleNode<>(null, MatchRule.ALL.matchHost("someHost1"), config1);
        RuleNode<SecurityFactory<SSLContext>> testedSslRule = new RuleNode<>(null, MatchRule.ALL.matchPort(2345), ssl2);
        AuthenticationContext testedCtx = new AuthenticationContext(testedConfigurationRule, testedSslRule);

        RuleNode<SecurityFactory<SSLContext>> initialSslRule = new RuleNode<>(null, MatchRule.ALL.matchHost("someHost2"), ssl1);
        AuthenticationContext ctx = new AuthenticationContext(null, initialSslRule)
                .with(testedCtx);

        assertExpectedRuleNode(ctx.authRules, config1, MatchRule.ALL.matchHost("someHost1"));

        assertNull(ctx.authRules.getNext());

        assertExpectedRuleNode(ctx.sslRules, ssl1, MatchRule.ALL.matchHost("someHost2"));

        RuleNode<SecurityFactory<SSLContext>> secondSsl = ctx.sslRules.getNext();
        assertExpectedRuleNode(secondSsl, ssl2, MatchRule.ALL.matchPort(2345));

        assertNull(secondSsl.getNext());
    }

    @Test
    public void replaceRuleConfiguration() {
        RuleNode<AuthenticationConfiguration> initialRule = new RuleNode<>(
                new RuleNode<>(
                        new RuleNode<>(null, MatchRule.ALL.matchPort(3456), config3),
                        MatchRule.ALL.matchPort(2345), config2),
                MatchRule.ALL.matchPort(1234), config1);

        AuthenticationContext ctx = new AuthenticationContext(initialRule, null)
                .replacing(1, MatchRule.ALL.matchHost("someHost"), config4);

        assertExpectedRuleNode(ctx.authRules, config1, MatchRule.ALL.matchPort(1234));

        RuleNode<AuthenticationConfiguration> second = ctx.authRules.getNext();
        assertExpectedRuleNode(second, config4, MatchRule.ALL.matchHost("someHost"));

        RuleNode<AuthenticationConfiguration> third = second.getNext();
        assertExpectedRuleNode(third, config3, MatchRule.ALL.matchPort(3456));

        assertNull(third.getNext());
    }

    @Test
    public void replaceRuleSsl() {
        RuleNode<SecurityFactory<SSLContext>> initialRule = new RuleNode<>(
                new RuleNode<>(
                        new RuleNode<>(null, MatchRule.ALL.matchPort(3456), ssl3),
                        MatchRule.ALL.matchPort(2345), ssl2),
                MatchRule.ALL.matchPort(1234), ssl1);

        AuthenticationContext ctx = new AuthenticationContext(null, initialRule)
                .replacingSslContext(1, MatchRule.ALL.matchHost("someHost"), ssl4);

        assertExpectedRuleNode(ctx.sslRules, ssl1, MatchRule.ALL.matchPort(1234));

        RuleNode<SecurityFactory<SSLContext>> second = ctx.sslRules.getNext();
        assertExpectedRuleNode(second, ssl4, MatchRule.ALL.matchHost("someHost"));

        RuleNode<SecurityFactory<SSLContext>> third = second.getNext();
        assertExpectedRuleNode(third, ssl3, MatchRule.ALL.matchPort(3456));

        assertNull(third.getNext());
    }

    @Test
    public void withoutRuleConfiguration() {
        RuleNode<AuthenticationConfiguration> initialRule = new RuleNode<>(
                new RuleNode<>(
                        new RuleNode<>(null, MatchRule.ALL.matchPort(3456), config3),
                        MatchRule.ALL.matchPort(2345), config2),
                MatchRule.ALL.matchPort(1234), config1);

        AuthenticationContext ctx = new AuthenticationContext(initialRule, null)
                .without(1);

        assertExpectedRuleNode(ctx.authRules, config1, MatchRule.ALL.matchPort(1234));

        RuleNode<AuthenticationConfiguration> second = ctx.authRules.getNext();
        assertExpectedRuleNode(second, config3, MatchRule.ALL.matchPort(3456));

        assertNull(second.getNext());
    }

    @Test
    public void withoutRuleSsl() {
        RuleNode<SecurityFactory<SSLContext>> initialRule = new RuleNode<>(
                new RuleNode<>(
                        new RuleNode<>(null, MatchRule.ALL.matchPort(3456), ssl3),
                        MatchRule.ALL.matchPort(2345), ssl2),
                MatchRule.ALL.matchPort(1234), ssl1);

        AuthenticationContext ctx = new AuthenticationContext(null, initialRule)
                .withoutSsl(1);

        assertExpectedRuleNode(ctx.sslRules, ssl1, MatchRule.ALL.matchPort(1234));

        RuleNode<SecurityFactory<SSLContext>> second = ctx.sslRules.getNext();
        assertExpectedRuleNode(second, ssl3, MatchRule.ALL.matchPort(3456));

        assertNull(second.getNext());
    }

    private <T> void assertExpectedRuleNode(RuleNode<T> rn, T expectedConfiguration, MatchRule expectedRule) {
        assertNotNull(rn);
        assertEquals(expectedConfiguration, rn.getConfiguration());
        assertEquals(expectedRule, rn.getRule());
    }

}
