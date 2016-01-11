/*********************************************************************************
 * Copyright (c) 2013 Forschungszentrum Juelich GmbH 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * (1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the disclaimer at the end. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * 
 * (2) Neither the name of Forschungszentrum Juelich GmbH nor the names of its 
 * contributors may be used to endorse or promote products derived from this 
 * software without specific prior written permission.
 * 
 * DISCLAIMER
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ********************************************************************************/

package eu.unicore.security.wsutil.client;

import java.util.List;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.message.MessageUtils;
import org.apache.cxf.phase.Phase;
import org.apache.log4j.Logger;

import eu.unicore.security.wsutil.SecuritySessionUtils;
import eu.unicore.security.wsutil.SessionIDServerOutHandler;
import eu.unicore.util.Log;
import eu.unicore.util.httpclient.IClientConfiguration;
import eu.unicore.util.httpclient.SessionIDProvider;

/**
 * A client handler that sets the security session header.
 * 
 * The outgoing session ID can be provided by the {@link SessionIDProvider}
 * interface provided via the message context
 *  
 * @author schuller
 * @author K. Benedyczak
 */
public class SessionIDOutHandler extends AbstractSoapInterceptor implements Configurable {
	private static final Logger log = Log.getLogger(Log.CLIENT, SessionIDOutHandler.class);
	private IClientConfiguration settings;
	private static ThreadLocal<Boolean> skip = new ThreadLocal<Boolean>();
	
	
	public SessionIDOutHandler() {
		super(Phase.PRE_PROTOCOL);
		getBefore().add(TDOutHandler.class.getName());
		getBefore().add(ExtendedTDOutHandler.class.getName());
	}

	public synchronized void handleMessage(SoapMessage message) {
		if(!MessageUtils.isOutbound(message))
			return;

		String sessionID = null;
		
		Boolean doSkip = skip.get();
		if (doSkip != null && doSkip)
		{
			log.debug("Security session will not be used for this call");
			setSkip(false);
			return;
		}

		String targetUrl = (String) message.getContextualProperty(SecuritySessionUtils.SESSION_TARGET_URL);
		SessionIDProvider idProvider = settings.getSessionIDProvider();
		if (idProvider == null)
		{
			log.debug("No security session provider is installed");
			return;
		}
		
		sessionID=idProvider.getSessionID(targetUrl, settings);
		if(sessionID==null)
		{
			log.debug("No security session will be used for the request");
			return;
		}
		
		log.debug("Found session id for the request, using it: " + sessionID);
		Header header=SessionIDServerOutHandler.buildHeader(sessionID,-1);
		List<Header> h = message.getHeaders();
		h.add(header);
		message.put(SecuritySessionUtils.REUSED_MARKER_KEY, sessionID);
	}

	@Override
	public void configure(IClientConfiguration properties)
	{
		this.settings = properties;
	}
	
	/**
	 * Allows to set (or clear) the skip flag. If skip flag is set then the handler won't use session id
	 * even if available and matching. 
	 * This is a thread local feature.
	 * <p>
	 * Important: the flag is automatically cleared after each handler invocation, i.e. one have to set it before each
	 * network call.
	 * 
	 * @param how
	 */
	public static void setSkip(boolean how)
	{
		skip.set(how);
	}
}


