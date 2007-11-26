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

package net.oauth.example.provider.servlets;

import java.io.*;

import javax.servlet.*;
import javax.servlet.http.*;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthMessage;
import net.oauth.example.provider.core.SampleOAuthProvider;
import net.oauth.server.OAuthServlet;

/**
 * A text servlet to echo incoming "echo" param along with userId
 *
 * @author Praveen Alavilli
 */
public class EchoServlet extends HttpServlet {
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        
        String param = request.getParameter("echo");
        
        try{
            OAuthMessage requestMessage = OAuthServlet.getMessage(request, null);
            
            OAuthAccessor accessor = SampleOAuthProvider.getAccessor(requestMessage);
            
            String userId = (String)accessor.user;
            // verify the signature
            requestMessage.validateSignature(accessor);
            
            response.setContentType("text/plain");
            PrintWriter out = response.getWriter();
            // Try it twice:
            out.println(param + " [Your UserId:" + userId + "]");
            out.close();
            
        } catch (Exception e){
            SampleOAuthProvider.handleException(e, request, response);
        }
        
    }
}
