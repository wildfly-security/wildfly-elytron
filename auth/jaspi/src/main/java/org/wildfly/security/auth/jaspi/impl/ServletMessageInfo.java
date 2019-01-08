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

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.auth.jaspi._private.ElytronMessages.log;

import javax.security.auth.message.MessageInfo;
import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestWrapper;
import javax.servlet.ServletResponse;
import javax.servlet.ServletResponseWrapper;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A servlet profile specific {@link MessageInfo} that ensures the request and response types remain valid and allows wrapping
 * an existing message info during validateRequest and unwrapping during secureResponse.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ServletMessageInfo extends ElytronMessageInfo {

    /*
     * Referenced in the Elytron Web Integration.
     */

    /**
     * Set the request message ensuring that it is an instance of {@link HttpServletRequest}, also ensure wrapping only occurs
     * during calls to validateRequest and unwrapping occurs during calls to secureResponse.
     *
     * @param requestMessage the request message.
     */
    @Override
    public void setRequestMessage(Object requestMessage) {
        checkNotNullParam("requestMessage", requestMessage);
        if (requestMessage instanceof HttpServletRequest == false) {
            throw log.invalidMessageType(requestMessage.getClass().getName(), HttpServletRequest.class.getName());
        }

        switch (getState()) {
            case NEW:
                super.setRequestMessage(requestMessage);
                break;
            case VALIDATE: {
                ServletRequest current = (ServletRequest) getRequestMessage();
                ServletRequest unwrapped = (HttpServletRequest) requestMessage;
                while (unwrapped != null) {
                    if (unwrapped == current) {
                        super.setRequestMessage(requestMessage);
                        return;
                    }
                    unwrapped = unwrap(unwrapped);
                }
                throw log.messageDoesNotWrapExistingMessage(HttpServletRequest.class.getName());
            }
            case SECURE: {
                ServletRequest unwrapped = (ServletRequest) getRequestMessage();
                while (unwrapped != null) {
                    if (requestMessage == unwrapped) {
                        super.setRequestMessage(requestMessage);
                        return;
                    }
                    unwrapped = unwrap(unwrapped);
                }
                throw log.messageDoesNotUnWrapExistingMessage(HttpServletRequest.class.getName());
            }
            default:
                throw log.messageSettingNotAllowed(HttpServletRequest.class.getName());
        }
    }

    /**
     * Set the response message ensuring that it is an instance of {@link HttpServletResponse}, also ensure wrapping only occurs
     * during calls to validateRequest and unwrapping occurs during calls to secureResponse.
     *
     * @param responseMessage the response message.
     */
    @Override
    public void setResponseMessage(Object responseMessage) {
        checkNotNullParam("responseMessage", responseMessage);
        if (responseMessage instanceof HttpServletResponse == false) {
            throw log.invalidMessageType(responseMessage.getClass().getName(), HttpServletResponse.class.getName());
        }

        switch (getState()) {
            case NEW:
                super.setResponseMessage(responseMessage);
                break;
            case VALIDATE: {
                ServletResponse current = (ServletResponse) getResponseMessage();
                ServletResponse unwrapped = (HttpServletResponse) responseMessage;
                while (unwrapped != null) {
                    if (unwrapped == current) {
                        super.setResponseMessage(responseMessage);
                        return;
                    }
                    unwrapped = unwrap(unwrapped);
                }
                throw log.messageDoesNotWrapExistingMessage(HttpServletResponse.class.getName());
            }
            case SECURE: {
                ServletResponse unwrapped = (ServletResponse) getRequestMessage();
                while (unwrapped != null) {
                    if (responseMessage == unwrapped) {
                        super.setResponseMessage(responseMessage);
                        return;
                    }
                    unwrapped = unwrap(unwrapped);
                }
                throw log.messageDoesNotUnWrapExistingMessage(HttpServletResponse.class.getName());
            }
            default:
                throw log.messageSettingNotAllowed(HttpServletResponse.class.getName());
        }
    }

    private ServletRequest unwrap(ServletRequest servletRequest) {
        if (servletRequest instanceof ServletRequestWrapper) {
            return ((ServletRequestWrapper) servletRequest).getRequest();
        }

        return null;
    }

    private ServletResponse unwrap(ServletResponse servletResponse) {
        if (servletResponse instanceof ServletResponseWrapper) {
            return ((ServletResponseWrapper) servletResponse).getResponse();
        }

        return null;
    }

}
