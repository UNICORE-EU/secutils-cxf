/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Jun 2, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.xfireutil.client;

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.message.MessageUtils;
import org.apache.cxf.phase.Phase;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.unicore.security.etd.TrustDelegation;
import eu.unicore.security.user.UserAssertion;
import eu.unicore.security.xfireutil.WSSecHeader;
import eu.unicore.util.Log;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;

/**
 * Trust delegation handler for outgoing messages. It merely inserts configured 
 * TD chain into SOAP header along with User assertion if needed.
 * <p>
 * From the version 1.3.4 system property eu.unicore.security.xfireutil.wssecCompilant can be used
 * to control where the ETD and User assertions are placed. If the property value is 'true' then
 * are inserted under wssec:Security element. If the property is false or undefined then assertions
 * are placed directly under the soap header. Note that it is planned to change the default behavior in 
 * the future versions.
 *   
 * @author K. Benedyczak
 * @author schuller
 */
public class TDOutHandler extends AbstractSoapInterceptor {

	private static final Logger logger = Log.getLogger(Log.SECURITY, TDOutHandler.class);
	public static final String WSSEC_COMPILANT_PROPERTY = "eu.unicore.security.xfireutil.wssecComilant";

	private List<TrustDelegation> assertionList=null;

	private List<Element> assertionListAsJDOM=null;
	private Element userAssertionAsJDOM;
	private boolean useWssecElem;

	/**
	 * Add specified TD tokens into a header.
	 * User assertion won't be inserted. 
	 * @param tdChain Trust delegation tokens
	 */
	public TDOutHandler(List<TrustDelegation> tdChain)
	{
		super(Phase.PRE_PROTOCOL);
		init(tdChain, null, null, null);		
	}

	/**
	 * Add specified TD tokens into a header.
	 * The supplied User assertion will be inserted as well. 
	 * @param tdChain Trust delegation tokens
	 * @param userAssertion User assertion to be added
	 */
	public TDOutHandler(List<TrustDelegation> tdChain, UserAssertion userAssertion)
	{
		super(Phase.PRE_PROTOCOL);
		init(tdChain,userAssertion);
	}
	
	/**
	 * Add specified TD tokens into a header.
	 * Also User assertion will be inserted, specifying consignor and user. 
	 * @param tdChain Trust delegation tokens
	 * @param userDN Requested User's DN
	 * @param callerDN Consignor's DN
	 */
	public TDOutHandler(List<TrustDelegation> tdChain, 
			String userDN, String callerDN)
	{
		super(Phase.PRE_PROTOCOL);
		init(tdChain, null, userDN, callerDN);	
	}

	/**
	 * Add specified TD tokens into a header.
	 * Also User assertion will be inserted, specifying consignor and user. 
	 * @param tdChain Trust delegation tokens
	 * @param userCert User's Certificate
	 * @param callerDN COnsignor's DN
	 */
	public TDOutHandler(List<TrustDelegation> tdChain, 
			X509Certificate userCert, String callerDN)
	{
		super(Phase.PRE_PROTOCOL);
		init(tdChain, userCert, null, callerDN);
	}

	protected TDOutHandler()
	{
		super(Phase.PRE_PROTOCOL);
		initHandler();
	}
	
	protected void initHandler()
	{
		getBefore().add(DSigOutHandler.class.getName());
		String prop = System.getProperty(WSSEC_COMPILANT_PROPERTY);
		if (prop != null && prop.equals("true"))
		{
			useWssecElem = true;
			logger.debug("ETD and User assertions will be placed under the " +
			"wssec:Security element");
		} else
		{
			useWssecElem = false;
			logger.debug("ETD and User assertions will be placed directly " +
			"under the SOAP header for backwards compatibility.");
		}		
	}
	
	protected void init(List<TrustDelegation> tdChain, UserAssertion userAssertion)
	{
		initHandler();
		initJDOM(tdChain,userAssertion);
	}
	
	protected void init(List<TrustDelegation> tdChain, 
			X509Certificate userCert, String userDN, String callerDN)
	{
		initHandler();
		UserAssertion userA = createUserAssertion(userCert,userDN,callerDN);
		initJDOM(tdChain,userA);
	}

	
	protected UserAssertion createUserAssertion(X509Certificate userCert, String userDN, String callerDN)
	{
		UserAssertion userA = null;
		if (userCert != null && callerDN != null)
		{
			X509Certificate[] userCC = new X509Certificate[]{userCert};
			try
			{
				userA = new UserAssertion(callerDN, userCC);
			} catch(Exception e)
			{
				logger.fatal("Can't create USER assertion: ", e);
			}
		} else if (userDN != null && callerDN != null)
			userA = new UserAssertion(callerDN, userDN);

		return userA;
	}
	
	
	protected void initJDOM(List<TrustDelegation>tdChain,UserAssertion userA){
		assertionListAsJDOM = null;
		assertionList = (tdChain != null) ?
				tdChain : new ArrayList<TrustDelegation>();
		if (assertionList.size() != 0)
		{
			assertionListAsJDOM = new ArrayList<Element>();
			try
			{
				for (TrustDelegation td: assertionList){
						Element el=DOMUtils.readXml(td.getXML().newInputStream()).getDocumentElement();
						assertionListAsJDOM.add(el);
				}
				logger.debug("Initialised TD Outhandler with " +
						"TD chain of length = " + assertionList.size());
			} catch(Exception e)
			{
				logger.warn("Can't create JDOM representation of TD assertion.",e);
				assertionListAsJDOM = null;
			}
		}
		
		userAssertionAsJDOM = null;
		if (userA != null)
		{
			try
			{
				AssertionDocument user = userA.getXML();
				userAssertionAsJDOM=DOMUtils.readXml(user.newInputStream()).getDocumentElement();
			} catch(Exception e)
			{
				logger.fatal("Can't create USER assertion: ", e);
				return;
			}
		}
	}
	
	public void handleMessage(SoapMessage message)
	{
		//do nothing if not a client call 
		//(is probably a misconfiguration, but make sure anyway)
		if(!MessageUtils.isOutbound(message))
			return;

		if (assertionListAsJDOM == null && userAssertionAsJDOM == null)
		{
			logger.debug("Neither TD nor User assertion available.");
			return;
		}
		
		if(assertionListAsJDOM != null && logger.isTraceEnabled())
		{
			logger.trace("TD DUMP begin");
			for(TrustDelegation td: assertionList)
				logger.trace(td.getXML().toString());
			logger.trace("TD DUMP end");		
		}

		List<Header> h = message.getHeaders();
		Element insertionPoint = null;

		if (useWssecElem)
		{
			WSSecHeader sec = new WSSecHeader(true);
			insertionPoint = sec.getOrInsertWSSecElement(h);
		}
		
		if (assertionListAsJDOM != null)
		{
			for (Element e: assertionListAsJDOM){
				if(useWssecElem){
					Document parent=insertionPoint.getOwnerDocument();
					insertionPoint.appendChild(parent.importNode(e,true));
				}
				else{
					Header header=new Header(AssertionDocument.type.getDocumentElementName(),e);
					h.add(header);
				}
			}
		}
		if (userAssertionAsJDOM != null)
		{
			if(useWssecElem){
				Document parent=insertionPoint.getOwnerDocument();
				insertionPoint.appendChild(parent.importNode(userAssertionAsJDOM,true));
			}
			else{
				Header header=new Header(AssertionDocument.type.getDocumentElementName(),userAssertionAsJDOM);
				h.add(header);
			}
			if (logger.isTraceEnabled()){
				try
				{
					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					DOMUtils.writeXml(userAssertionAsJDOM, bos);
					logger.trace("User assertion:\n" + bos.toString());
				} catch(Exception e)
				{
					logger.warn("Can't output user assertion", e);
				}
			}
		}
	}
}


