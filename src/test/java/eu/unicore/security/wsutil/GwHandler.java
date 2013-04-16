/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Jun 2, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import java.io.ByteArrayOutputStream;
import java.util.List;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.phase.Phase;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import eu.unicore.security.consignor.ConsignorAssertion;

/**
 * Inserts assertion as GW does.
 * @author K. Benedyczak
 */
public class GwHandler extends AbstractSoapInterceptor 
{
	private static final Logger logger = Logger.getLogger(GwHandler.class);

	private Element assertionAsJDOM;

	/**
	 * Creates handler's object. It won't work until configured with reinit() method.
	 * @param tdChain Trust delegation tokens
	 * @param userCert User's Certificate
	 * @param callerDN COnsignor's DN
	 */
	public GwHandler()
	{
		super(Phase.SETUP);
	}

	/**
	 * Updated this object state so it will add specified TD tokens into a header.
	 * Also User assertion will be inserted, specifying consignor and user. 
	 * @param tdChain Trust delegation tokens
	 * @param userCert User's Certificate
	 * @param callerDN COnsignor's DN
	 */
	public synchronized void reinit(ConsignorAssertion assertion)
	{

		assertionAsJDOM = null;
		try
		{
			AssertionDocument ad = assertion.getXMLBeanDoc();
			Document doc=DOMUtils.readXml(ad.newInputStream());
			assertionAsJDOM=doc.getDocumentElement();
		} catch(Exception e)
		{
			logger.fatal("Can't create CONSIGNOR assertion: ", e);
			return;
		}
	}


	public void handleMessage(SoapMessage context)
	{
		List<Header>h=context.getHeaders();

		if (assertionAsJDOM != null)
		{
			Header header=new Header(AssertionDocument.type.getDocumentElementName(),assertionAsJDOM);
			h.add(header);

			if (logger.isTraceEnabled()){
				try
				{
					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					DOMUtils.writeXml(assertionAsJDOM, bos);
					logger.trace("Consignor assertion:\n" + bos.toString());
				} catch(Exception e)
				{
					logger.warn("Can't output consignor assertion", e);
				}
			}
		}
	}
}


