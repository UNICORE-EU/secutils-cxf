/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Mar 7, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.message.MessageUtils;
import org.apache.cxf.phase.Phase;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.security.wsutil.WSSecHeader;
import eu.unicore.util.Log;
import eu.unicore.util.httpclient.IClientConfiguration;

/**
 * This handler inserts SAML attribute assertions into the request. 
 * Of course this handler should be used in client mode.
 * The assertions to be sent are retrieved from the {@link IClientProperties}'s 
 * extraSecurityTokens map. One should put there assertions either as a list of parsed
 * object of type List&lt;Assertion> or as a list of raw XML elements of type 
 * List&lt;Element>. In the first case assertions should be stored under the key
 * SAMLAttributePushInHandler.PUSHED_ASSERTIONS, in the latter under the key 
 * SAMLAttributePushOutHandler.PUSHED_RAW_ASSERTIONS.
 * If both are found then the all assertions are sent.
 * 
 * @author K. Benedyczak
 */
public class SAMLAttributePushOutHandler extends AbstractSoapInterceptor implements Configurable
{
	private static final Logger log = Log.getLogger(Log.SECURITY, SAMLAttributePushOutHandler.class);
	public static final String PUSHED_RAW_ASSERTIONS = SAMLAttributePushOutHandler.class.getName() + 
						".RAW-SAML-TO-PUSH";
	/**
	 * Key used in security context to mark value with the SAML assertions list received
	 */
	public static final String PUSHED_ASSERTIONS = "SAMLPushedassertions";
	protected List<Element> toBeInserted;
	protected List<Assertion> origList;

	/**
	 * Default constructor. After using it the object should be initialized later
	 * using configure() method.
	 */
	public SAMLAttributePushOutHandler() 
	{
		super(Phase.POST_INVOKE);
		toBeInserted = new ArrayList<Element>();
		getBefore().add(DSigOutHandler.class.getName());
	}

	/**
	 * Initializes this handler with a list of assertions.
	 * @throws IOException 
	 * @throws JDOMException 
	 */
	public SAMLAttributePushOutHandler(List<Assertion> assertions) throws IOException 
	{
		this();
		convertToJDOM(assertions);
		origList = assertions;
	}
	

	@Override
	public void configure(IClientConfiguration properties)
	{
		Map<String, Object> secContext = properties.getExtraSecurityTokens();
		if (secContext == null)
		{
			log.debug("Extra security tokens are not set; SAML attributes won't be sent.");
			return;
		}
		Object assertionsO = secContext.get(PUSHED_ASSERTIONS);
		Object assertionsRawO = secContext.get(
				SAMLAttributePushOutHandler.PUSHED_RAW_ASSERTIONS);
		if (assertionsO != null)
		{
			@SuppressWarnings("unchecked")
			List<Assertion> assertions = (List<Assertion>) assertionsO;
			try
			{
				convertToJDOM(assertions);
				origList = assertions;
			} catch (Exception e)
			{
				log.error("Error when parsing SAML assertions.", e);
			}
		}
		
		if (assertionsRawO != null)
		{
			@SuppressWarnings("unchecked")
			List<Element> assertionsRaw = (List<Element>) assertionsRawO;
			toBeInserted.addAll(assertionsRaw);
		}
		if (toBeInserted.size() == 0)
		{
			log.debug("Thre are no SAML assertions in extra security " +
					"tokens; SAML attributes won't be sent.");
			return;
		}
		log.debug("Found SAML assertions to be sent, applying them");
	}
	
	public void handleMessage(SoapMessage message)
	{
		if(!MessageUtils.isOutbound(message))
		{
			log.warn("Handler " + SAMLAttributePushOutHandler.class.getName() + 
				" used in non-client mode, what does not make sense. " +
				"Check your configuration.");
			return;
		}
		
		if (toBeInserted == null || toBeInserted.size() == 0)
			return;
		
		log.debug("Adding SAML assertions to the request's header.");
		List<Header> h = message.getHeaders();
		WSSecHeader sec = new WSSecHeader(true);
		Element insertionPoint = sec.getOrInsertWSSecElement(h);
		
		for (Element o: toBeInserted)
		{
			if (log.isTraceEnabled())
			{
				try{
					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					DOMUtils.writeXml(o, bos);
					log.trace(bos.toString());
				}catch(Exception ex){
					log.warn("Can't output assertion", ex);
				}
			}
			Document parent=insertionPoint.getOwnerDocument();
			insertionPoint.appendChild(parent.importNode(o,true));
		}
	}
	
	protected void convertToJDOM(List<Assertion> rawAssertions) 
		throws IOException
	{
		for (Assertion a: rawAssertions)
		{
			AssertionDocument asDoc = a.getXML();
			try{
				Element elem = DOMUtils.readXml(asDoc.newInputStream()).getDocumentElement();
				toBeInserted.add(elem);
			}catch(Exception ex){
				throw new IOException(ex);
			}
		}
	}

	public List<Assertion> getOrigList()
	{
		return origList;
	}
}










