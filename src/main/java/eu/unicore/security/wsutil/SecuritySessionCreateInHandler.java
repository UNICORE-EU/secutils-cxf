/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.ICM file for licencing information.
 *
 * Created on May 31, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import java.util.UUID;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.phase.Phase;
import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import eu.unicore.security.SecurityTokens;
import eu.unicore.util.Log;

/**
 * Security in-handler for UNICORE. Creates a security session 
 * if no existing session id was provided by the client.
 * 
 * @author K. Benedyczak
 */
public class SecuritySessionCreateInHandler extends AbstractSoapInterceptor
{
	protected static final Logger logger = Log.getLogger(Log.SECURITY, SecuritySessionCreateInHandler.class);
	
	private final static long DEF_SESSION_LIFETIME = 60*60*1000;

	protected SecuritySessionStore sessionStore;
	private final long sessionLifetime;
	
	public SecuritySessionCreateInHandler(SecuritySessionStore sessionStore)
	{
		this(sessionStore, DEF_SESSION_LIFETIME);
	}
	
	public SecuritySessionCreateInHandler(SecuritySessionStore sessionStore, long sessionLifetime)
	{
		super(Phase.PRE_INVOKE);
		this.sessionStore = sessionStore;
		this.sessionLifetime = sessionLifetime;
	}

	@Override
	public void handleMessage(SoapMessage ctx)
	{
		SecurityTokens securityTokens = (SecurityTokens) ctx.get(SecurityTokens.KEY);
		if (securityTokens == null)
		{
			logger.error("No security info in headers. Wrong configuration: " +
					AuthInHandler.class.getCanonicalName() + " handler" +
					" must be configure before this Security session creation handler.");
			return;
		}
		
		if(Boolean.TRUE.equals(securityTokens.getContext().get(SecuritySessionUtils.REUSED_MARKER_KEY))){
			return;
		}
		
		createSession(securityTokens);
	}

	/**
	 * create a new session
	 *  
	 * @param securityTokens
	 */
	protected SecuritySession createSession(SecurityTokens securityTokens){
		SecuritySession session = null;
		String sessionID=UUID.randomUUID().toString();
		securityTokens.getContext().put(SecuritySessionUtils.SESSION_ID_KEY, sessionID);
		session = new SecuritySession(sessionID, securityTokens, sessionLifetime);
		sessionStore.storeSession(session, securityTokens);
		
		// make sure session info goes to the client
		SessionIDServerOutHandler.setSession(session);
		
		return session;
	}
	

	public static boolean haveSessionID(SoapMessage message)
	{
		return message.getContextualProperty(SecuritySessionUtils.REUSED_MARKER_KEY) != null;
	}

	public static String getSecuritySessionID(SoapMessage message)
	{
		String sessionID=null;
		Header header=message.getHeader(SecuritySessionUtils.headerQName);
		if(header!=null){
			Element hdr = (Element) header.getObject();		
			if(hdr!=null)
				sessionID = hdr.getTextContent(); 
		}
		return sessionID;
	}
}
