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
import net.oauth.OAuthProblemException;
import net.oauth.example.provider.core.SampleOAuthProvider;
import net.oauth.server.OAuthServlet;

/**
 * Access Token request handler
 *
 * @author Praveen Alavilli
 */
public class AccessTokenServlet extends HttpServlet {
    
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        // nothing at this point
    }
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        
        try{
            OAuthMessage requestMessage = OAuthServlet.getMessage(request, null);
            
            OAuthAccessor accessor = SampleOAuthProvider.getAccessor(requestMessage);
            
            // verify the signature
            requestMessage.validateSignature(accessor);
            
            // make sure token is authorized
            if(!accessor.isAuthorized()){
                 OAuthProblemException problem = new OAuthProblemException(
                        "token_not_authorized");
                throw problem;
            }
            // generate request_token and secret
            SampleOAuthProvider.generateAccessToken(accessor);
            
            response.setContentType("text/plain");
            PrintWriter out = response.getWriter();
            // Try it twice:
            out.println("oauth_token=" + accessor.accessToken 
                        + "&oauth_token_secret=" + accessor.tokenSecret + "&");
            out.close();
            
            
        } catch (Exception e){
            SampleOAuthProvider.handleException(e, request, response);
        }
    }
    
}
