/*
 * Copyright 2018 Red Hat, Inc.
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

package org.wildfly.security.auth.jaspi.impl;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.message.MessageInfo;

/**
 * An implementation of the {@link MessageInfo} interface.
 *
 * @see javax.security.auth.message.MessageInfo
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronMessageInfo implements MessageInfo {

    /*
     * The API description MessageInfo is so descriptive and the methods on the API describe the complete API the specification
     * may as well have included the implementation.
     */

    private final Map<Object, Object> map = new HashMap<>();
    private Object requestMessage;
    private Object responseMessage;
    private State state = State.NEW;

    /**
     * @see javax.security.auth.message.MessageInfo#getMap()
     */
    @Override
    public Map getMap() {
        return map;
    }

    /**
     * @see javax.security.auth.message.MessageInfo#getRequestMessage()
     */
    @Override
    public Object getRequestMessage() {
        return requestMessage;
    }

    /**
     * @see javax.security.auth.message.MessageInfo#getResponseMessage()
     */
    @Override
    public Object getResponseMessage() {
        return responseMessage;
    }

    /**
     * @see javax.security.auth.message.MessageInfo#setRequestMessage(java.lang.Object)
     */
    @Override
    public void setRequestMessage(Object requestMessage) {
        this.requestMessage = requestMessage;
    }

    /**
     * @see javax.security.auth.message.MessageInfo#setResponseMessage(java.lang.Object)
     */
    @Override
    public void setResponseMessage(Object responseMessage) {
        this.responseMessage = responseMessage;
    }

    /**
     * Set the current processing state for this {@link MessageInfo}.
     *
     * @param state the current processing state for this {@link MessageInfo}.
     */
    void setState(State state) {
        this.state = state;
    }

    /**
     * Get the current state for how this {@link MessageInfo} is being used.
     *
     * @return the current processing state for this {@link MessageInfo}.
     */
    protected State getState() {
        return state;
    }

    protected enum State {
        NEW, VALIDATE, SECURE, CLEAN;
    }

}
