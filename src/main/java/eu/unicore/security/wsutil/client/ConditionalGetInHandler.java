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

package eu.unicore.security.wsutil.client;

import javax.xml.namespace.QName;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.phase.Phase;
import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import eu.unicore.util.Log;

/**
 * WS client handler that retrieves the Etag and LastModified information 
 * from the "conditional get" SOAP headers sent by the server and puts it 
 * into thread local storage for later evaluation
 * 
 * @author schuller
 */
public class ConditionalGetInHandler extends AbstractSoapInterceptor
{
	private static final Logger logger = Log.getLogger(Log.CLIENT,ConditionalGetInHandler.class);

	private static final ThreadLocal<String>etag=new ThreadLocal<String>();

	private static final ThreadLocal<String>lastModified=new ThreadLocal<String>();

	private static final ThreadLocal<Boolean>notModified=new ThreadLocal<Boolean>();

	//header namespace
	public static final String CG_HEADER_NS="http://www.unicore.eu/unicore/ws";

	//header element name
	public static final String CG_HEADER="ConditionalGet";

	private static final String ETAG_HEADER="Etag";
	private static final String LASTMODIFIED_HEADER="LastModified";
	private static final String NOTMODIFIED_HEADER="NotModified";
	
	private final static QName headerQName=new QName(CG_HEADER_NS,CG_HEADER);
	private final static QName inmQName=new QName(CG_HEADER_NS,ETAG_HEADER);
	private final static QName imsQName=new QName(CG_HEADER_NS,LASTMODIFIED_HEADER);
	private final static QName notModifiedQName=new QName(CG_HEADER_NS,NOTMODIFIED_HEADER);
	
	public ConditionalGetInHandler(){
		super(Phase.PRE_INVOKE);
	}

	public void handleMessage(SoapMessage ctx)
	{
		notModified.set(Boolean.FALSE);
		
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

		Element notModEl=DOMUtils.getFirstChildWithName(hdr,notModifiedQName);
		if(notModEl!=null){
			notModified.set(Boolean.TRUE);
		}
		else{
			notModified.set(Boolean.FALSE);
		}

		if(logger.isDebugEnabled()){
			if(notModEl==null){
				logger.debug("Extracted ETag="+inm + " LastModidied="+ims);
			}
			else{
				logger.debug("Not modified");
			}
		}
		etag.set(inm);
		lastModified.set(ims);

	}

	public static String getEtag(){
		return etag.get();
	}

	public static String getLastModified(){
		return lastModified.get();
	}
	
	public static boolean isNotModified(){
		return notModified.get();
	}
}



