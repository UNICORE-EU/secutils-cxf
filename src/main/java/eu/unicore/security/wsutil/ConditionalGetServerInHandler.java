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
 * DEVELOPED IN THE CONTEXT OF THE OMII-EUROPE PROJECT.
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

package eu.unicore.security.wsutil;

import javax.xml.namespace.QName;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.phase.Phase;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Element;

import eu.unicore.util.Log;

/**
 * WS server-side handler that retrieves the Etag and LastModified information 
 * from the "conditional get" SOAP headers sent by the server and puts it 
 * into thread local storage for later evaluation
 * 
 * @author schuller
 */
public class ConditionalGetServerInHandler extends AbstractSoapInterceptor
{
	private static final Logger logger = Log.getLogger(Log.SERVICES,ConditionalGetServerInHandler.class);

	private static final ThreadLocal<String>etag=new ThreadLocal<String>();

	private static final ThreadLocal<String>lastModified=new ThreadLocal<String>();

	//header namespace
	public static final String CG_HEADER_NS="http://www.unicore.eu/unicore/ws";

	//header element name
	public static final String CG_HEADER="ConditionalGet";

	private static final String ETAG_HEADER="IfNoneMatch";
	private static final String LASTMODIFIED_HEADER="IfModifiedSince";
	
	private final static QName headerQName=new QName(CG_HEADER_NS,CG_HEADER);
	private final static QName inmQName=new QName(CG_HEADER_NS,ETAG_HEADER);
	private final static QName imsQName=new QName(CG_HEADER_NS,LASTMODIFIED_HEADER);
	
	public ConditionalGetServerInHandler(){
		super(Phase.PRE_INVOKE);
	}

	public void handleMessage(SoapMessage ctx)
	{
		// get the SOAP header
		Header header=ctx.getHeader(headerQName);
		if(header==null)return;

		// clean up any stuff from previous invocations
		etag.remove();
		lastModified.remove();

		Element hdr = (Element) header.getObject();		
		
		Element inmEl=DOMUtils.getFirstChildWithName(hdr,inmQName);
		String inm= inmEl!=null? inmEl.getTextContent() : null; 

		Element imsEl=DOMUtils.getFirstChildWithName(hdr,imsQName);
		String ims= imsEl!=null? imsEl.getTextContent() : null; 

		if(logger.isDebugEnabled()){
			logger.debug("Extracted IfNoneMatch="+inm + " IfModifiedSince="+ims);		
		}
		etag.set(inm);
		lastModified.set(ims);

	}

	/**
	 * get the etag value from the IfNoneMatch header
	 */
	public static String getIfNoneMatch(){
		return etag.get();
	}

	/**
	 * get the raw string value of the IfModifiedSince header
	 */
	public static String getIfModifiedSince(){
		return lastModified.get();
	}
	
}



