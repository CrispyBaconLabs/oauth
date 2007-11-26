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
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import net.oauth.example.provider.core.SampleOAuthProvider;
import net.oauth.server.OAuthServlet;

/**
 * Autherization request handler.
 *
 * @author Praveen Alavilli
 */
public class AuthorizationServlet extends HttpServlet {
    
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
           
            if(accessor.isAuthorized()){
                // already authorized send the user back
                returnToConsumer(request, response, accessor);
            } else {
                sendToAuthorizePage(request, response, accessor);
            }
        
        } catch (Exception e){
            SampleOAuthProvider.handleException(e, request, response);
        }
        
        
        
    }
    
    @Override 
    public void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws IOException, ServletException{
        
        try{
            OAuthMessage requestMessage = OAuthServlet.getMessage(request, null);
            
            OAuthAccessor accessor = SampleOAuthProvider.getAccessor(requestMessage);
            
            String userId = request.getParameter("userId");
            if(userId == null){
                sendToAuthorizePage(request, response, accessor);
            }
            // set userId in accessor and mark it as authorized
            SampleOAuthProvider.markAsAuthorized(accessor, userId);
            
            returnToConsumer(request, response, accessor);
            
        } catch (Exception e){
            SampleOAuthProvider.handleException(e, request, response);
        }
    }
    
    private void sendToAuthorizePage(HttpServletRequest request, 
            HttpServletResponse response, OAuthAccessor accessor)
    throws IOException, ServletException{
        String callback = request.getParameter("oauth_callback");
        String consumer_description = (String)accessor.consumer.getProperty("description");
        request.setAttribute("CONS_DESC", consumer_description);
        request.setAttribute("CALLBACK", callback);
        request.setAttribute("TOKEN", accessor.requestToken);
        request.getRequestDispatcher //
                    ("/authorize.jsp").forward(request,
                        response);
        
    }
    
    private void returnToConsumer(HttpServletRequest request, 
            HttpServletResponse response, OAuthAccessor accessor)
    throws IOException, ServletException{
        // send the user back to site's callBackUrl
        String callback = request.getParameter("oauth_callback");
        // if callback is not passed in, use the callback from config
        if(callback == null || callback.length() <=0 )
            callback = accessor.consumer.callbackURL;
        String token = accessor.requestToken;
        if (token != null) {
            callback = OAuth.addParameters(callback, "oauth_token", token);
        }
        response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
        response.setHeader("Location", callback);
    }
}
