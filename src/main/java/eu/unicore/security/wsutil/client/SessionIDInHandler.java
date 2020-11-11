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

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.phase.Phase;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Element;

import eu.unicore.security.wsutil.SecuritySessionUtils;
import eu.unicore.util.Log;
import eu.unicore.util.httpclient.IClientConfiguration;
import eu.unicore.util.httpclient.SessionIDProvider;

/**
 * A client handler that reads the security session ID header which is set by the
 * server.
 * 
 * @author schuller
 * @author K. Benedyczak
 */
public class SessionIDInHandler extends AbstractSoapInterceptor implements Configurable {
	private static final Logger log = Log.getLogger(Log.CLIENT, SessionIDInHandler.class);
	private static final ThreadLocal<String>currentSessionID=new ThreadLocal<String>();
	private IClientConfiguration configuration;
	
	public SessionIDInHandler() {
		super(Phase.INVOKE);
	}

	public synchronized void handleMessage(SoapMessage message) {
		log.trace("SessionIDInHandler invoked");
		currentSessionID.remove();
		Header header=message.getHeader(SecuritySessionUtils.headerQName);
		if(header==null)return;
		Element hdr = (Element) header.getObject();		
		
		Element id=DOMUtils.getFirstChildWithName(hdr,SecuritySessionUtils.idQName);
		String sessionID= id!=null? id.getTextContent() : null; 
		Element lt=DOMUtils.getFirstChildWithName(hdr,SecuritySessionUtils.ltQName);
		String lifetime= lt!=null? lt.getTextContent() : null; 

		if (sessionID != null && lifetime != null) 
		{
			log.debug("Server returned security session id=" + sessionID + " lifetime=" + lifetime);
			String targetUrl = (String) message.getContextualProperty(
					SecuritySessionUtils.SESSION_TARGET_URL);
			SessionIDProvider idProvider=configuration.getSessionIDProvider();
			if (idProvider != null)
			{
				log.debug("Registering session in the session provider");
				idProvider.registerSession(sessionID, targetUrl, Long.valueOf(lifetime), 
						configuration);
				currentSessionID.set(sessionID);
			}
		}
	}

	/**
	 * This method is useful for tests only. It returns the session id which was returned by the server
	 * during the last WS call. This is thread local, so only the same thread can access this information.
	 */
	public static String getSessionID(){
		return currentSessionID.get();
	}

	@Override
	public void configure(IClientConfiguration properties)
	{
		this.configuration = properties;
	}
}


