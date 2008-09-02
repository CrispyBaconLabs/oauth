/*
 * Copyright 2007 Netflix, Inc.
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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.server.OAuthServlet;

/**
 * A trivial consumer of the 'echo' service at Mediamatic.
 * 
 * @author John Kristian
 */
public class MediamaticConsumer extends HttpServlet {

    private static final String NAME = "mediamatic";

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        OAuthConsumer consumer = null;
        try {
            consumer = CookieConsumer.getConsumer(NAME, getServletContext());
            OAuthAccessor accessor = CookieConsumer.getAccessor(request,
                    response, consumer);
            List<OAuth.Parameter> parameters = OAuthServlet
                    .getParameters(request);
            response.setContentType("text/plain");
            // Try it twice:
            echo(accessor, parameters, response);
            echo(accessor, parameters, response);
        } catch (Exception e) {
            CookieConsumer.handleException(e, request, response, consumer);
        }
    }

    private static void echo(OAuthAccessor accessor,
            List<OAuth.Parameter> parameters, ServletResponse result)
            throws OAuthException, IOException, URISyntaxException {
        URL serviceURL = (new URL((URL) accessor.consumer
                .getProperty("serviceProvider.baseURL"),
                "services/rest/?method=anymeta.test.echo"));
        OAuthMessage response = CookieConsumer.CLIENT.invoke(accessor,
                serviceURL.toExternalForm(), parameters);
        OutputStream out = result.getOutputStream();
        InputStream in = response.getBodyAsStream();
        try {
            byte[] buffer = new byte[32];
            int len = 0;
            while (0 < (len = in.read(buffer, 0, buffer.length))) {
                out.write(buffer, 0, len);
            }
            out.write('\n');
        } finally {
            in.close();
        }
    }

    private static final long serialVersionUID = 1L;

}
