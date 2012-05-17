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
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.Phase;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.security.xfireutil.client.DSigOutHandler;

/**
 * This handler inserts a simple SOAP assertion into WSS security header.
 * 
 * @author K. Benedyczak
 */
public class ExtraSAMLOutHandler extends AbstractSoapInterceptor
{
	public ExtraSAMLOutHandler()
	{
		super(Phase.SETUP);
		getBefore().add(DSigOutHandler.class.getName());
	}
	
	public void handleMessage(SoapMessage context)
	{
		System.out.println("Inserting additional SAML assertion into wss:Security");
		List<Header>h=context.getHeaders();
		WSSecHeader sec = new WSSecHeader(true);
		Element wsSecEl = sec.getOrInsertWSSecElement(h);
		try{
			Assertion a = new Assertion();
			Document doc=DOMUtils.readXml(a.getXML().newInputStream());
			Document parent=wsSecEl.getOwnerDocument();
			wsSecEl.appendChild(parent.importNode(doc.getDocumentElement(),true));
		}catch(Exception e){
			throw new Fault(e);
		}
		System.out.println("Additional element added");
	}
}










