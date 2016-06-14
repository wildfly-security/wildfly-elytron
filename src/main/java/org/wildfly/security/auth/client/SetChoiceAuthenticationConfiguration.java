/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.wildfly.security.auth.client;

import java.io.IOException;
import java.util.function.BiPredicate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * @author <a href="mailto:kkhan@redhat.com">Kabir Khan</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetChoiceAuthenticationConfiguration extends AuthenticationConfiguration {
    private final BiPredicate<Class<? extends ChoiceCallback>, String> matchPredicate;
    private final String choice;

    SetChoiceAuthenticationConfiguration(final AuthenticationConfiguration parent, final BiPredicate<Class<? extends ChoiceCallback>, String> matchPredicate,
                                         final String choice) {
        super(parent, true);
        this.matchPredicate = matchPredicate;
        this.choice = choice;
    }

    void handleCallback(final Callback[] callbacks, final int index) throws UnsupportedCallbackException, IOException {
        Callback callback = callbacks[index];
        if (callback instanceof ChoiceCallback) {
            ChoiceCallback choiceCallback = (ChoiceCallback) callback;
            if (matchPredicate.test(choiceCallback.getClass(), choiceCallback.getPrompt())) {
                //TODO handle multiple selections etc.
                if (choice == null) {
                    choiceCallback.setSelectedIndex(choiceCallback.getDefaultChoice());
                    return;
                } else {
                    String[] choices = choiceCallback.getChoices();
                    for (int i = 0; i < choices.length; i++) {
                        if (choice.equals(choices[i])) {
                            choiceCallback.setSelectedIndex(i);
                            return;
                        }
                    }
                }
            }
        }
        super.handleCallback(callbacks, index);
    }

    @Override
    AuthenticationConfiguration reparent(AuthenticationConfiguration newParent) {
        return new SetChoiceAuthenticationConfiguration(newParent, matchPredicate, choice);
    }
}
