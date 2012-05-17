/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Mar 7, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.xfireutil;

import java.util.List;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.phase.Phase;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.unicore.security.xfireutil.client.DSigOutHandler;

/**
 * This handler inserts a simple element into WSS security header.
 * 
 * @author K. Benedyczak
 */
public class AdditionalOutHandler extends AbstractSoapInterceptor
{
	public AdditionalOutHandler()
	{
		super(Phase.PRE_PROTOCOL);
		getBefore().add(DSigOutHandler.class.getName());
	}
	
	public void handleMessage(SoapMessage context)
	{
		System.out.println("Inserting additional element");
		List<Header>h = context.getHeaders();
		
		WSSecHeader sec = new WSSecHeader(true);
		Element wsSecEl = sec.getOrInsertWSSecElement(h);
		Document doc = DOMUtils.createDocument();
		Element added = doc.createElementNS("http://test.org", "tol:Tola");
		Document parent=wsSecEl.getOwnerDocument();
		wsSecEl.appendChild(parent.importNode(added,true));
		System.out.println("Additional element added");
	}
}










