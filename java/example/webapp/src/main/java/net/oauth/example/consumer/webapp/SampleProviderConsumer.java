/*
 * Copyright 2007 AOL, LLC.
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

package net.oauth.example.consumer.webapp;

import java.io.*;

import javax.servlet.*;
import javax.servlet.http.*;
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthMessage;
import net.oauth.server.OAuthServlet;

/**
 * Consumer for Sample OAuth Provider
 * @author Praveen Alavilli
 */
public class SampleProviderConsumer extends HttpServlet {
       private static final String NAME = "sample";

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            consumer = CookieConsumer.newConsumer(NAME, config);
            CookieConsumer.ALL_CONSUMERS.add(consumer);
        } catch (IOException e) {
            throw new ServletException(e);
        }
    }

    private OAuthConsumer consumer;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            OAuthAccessor accessor = CookieConsumer.getAccessor(request,
                    response, consumer);
            OAuthMessage message = OAuthServlet.getMessage(request, null);
            message.addParameter(new OAuth.Parameter("oauth_token",
                    accessor.accessToken));
            message.addParameter(new OAuth.Parameter("echo", "What's my UserId?"));
            response.setContentType("text/plain");
            PrintWriter out = response.getWriter();
            out.println("Sample Provider said:");
            // Try it twice:
            out.println(invoke(accessor, message));
            out.println(invoke(accessor, message));
        } catch (Exception e) {
            CookieConsumer.handleException(e, request, response, consumer);
        }
    }

    private String invoke(OAuthAccessor accessor, OAuthMessage message)
            throws Exception {
        OAuthMessage result = CookieConsumer.CLIENT.invoke(accessor,
                "http://localhost:8084/OAuthProvider/echo", message
                        .getParameters());
        String responseBody = result.getBodyAsString();
        return responseBody;
    }

    private static final long serialVersionUID = 1L;

    
}
