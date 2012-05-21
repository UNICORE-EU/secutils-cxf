/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Mar 7, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.xfireutil;

import java.util.List;

import javax.xml.namespace.QName;

import org.apache.cxf.binding.soap.SoapHeader;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.log4j.Logger;
import org.apache.ws.security.WSConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.unicore.security.util.Log;



/**
 * This class handles insertion of WS Security header element in terms of 
 * JDOM. It supports SOAP 1.1 only. Similar code can be found in apache wssec
 * however as it operates on DOM, for sake of efficiency we use custom implementation.
 *   
 * @author K. Benedyczak
 */
public class WSSecHeader
{
	private static final Logger log = Log.getLogger(Log.SECURITY, WSSecHeader.class);
	public static final String SOAP11_URI = 
			"http://schemas.xmlsoap.org/soap/envelope/";

	public static final String WSSE_NS_URI = 
			"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

	public static final String WSSE_LN = "Security";
	public static final String WSSE_PREFIX = "wsse";

	public static final String ATTR_ACTOR = "actor";
	public static final String ATTR_UNDERSTAND = "mustUnderstand";


	private final String actor;
	private final boolean mustUnderstand;

	/**
	 * Creates instance with no actor set.
	 * @param mustUnderstand
	 */
	public WSSecHeader(boolean mustUnderstand)
	{
		this.actor = null;
		this.mustUnderstand = mustUnderstand;
	}

	/**
	 * Creates instance with actor set.
	 * @param actor
	 * @param mustUnderstand
	 */
	public WSSecHeader(String actor, boolean mustUnderstand)
	{
		this.actor = actor;
		this.mustUnderstand = mustUnderstand;
	}

	public Element getOrInsertWSSecElement(List<Header> headers)
	{

		//TODO
		//if (!isSOAP11(header))
		//	throw new Exception("Unsupported SOAP version");

		Element ret = findWSSecElement(headers);
		if (ret != null)
		{
			log.debug("Found existing WSSec header element");
			return ret;
		}

		ret = createWSSecElement(headers);
		return ret;
	}

	private Element createWSSecElement(List<Header> headers)
	{
		Document doc = DOMUtils.createDocument();
		Element newWsSec = doc.createElementNS(WSSE_NS_URI, "wsse:Security");
		newWsSec.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:wsse", WSConstants.WSSE_NS);
		SoapHeader sh = new SoapHeader(new QName(WSSE_NS_URI, "Security"), newWsSec);
		sh.setMustUnderstand(mustUnderstand);
		headers.add(0, sh);
		return newWsSec;
	}

	private static final QName wsse=new QName(WSSE_NS_URI, WSSE_LN);

	/**
	 * get the WSSec header from the list of SOAP headers, if it exists
	 * 
	 * @param headers
	 * @return
	 */
	public Element findWSSecElement(List<Header> headers)
	{
		for(Header h: headers){
			System.out.println("header "+h.getName());
			if(!h.getName().equals(wsse))continue;

			Element e = (Element)h.getObject();
			boolean isActorSet=e.hasAttributeNS(SOAP11_URI, ATTR_ACTOR);
					 
			if (!isActorSet && actor == null)
				return e;
			
			String a=e.getAttributeNS(SOAP11_URI, ATTR_ACTOR);
			if (actor != null && actor.equals(a))
				return e;
		}

		return null;
	}

}
