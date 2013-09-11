/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Jun 2, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil.client;

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.binding.soap.saaj.SAAJOutInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.message.MessageUtils;
import org.apache.cxf.phase.Phase;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import eu.unicore.security.etd.TrustDelegation;
import eu.unicore.security.user.UserAssertion;
import eu.unicore.security.wsutil.SecuritySessionUtils;
import eu.unicore.security.wsutil.WSSecHeader;
import eu.unicore.util.Log;

/**
 * Trust delegation handler for outgoing messages. It merely inserts configured 
 * TD chain into SOAP header along with User assertion if needed.
 * The assertions are inserted under the wssec:Security element.
 * 
 * @author K. Benedyczak
 * @author schuller
 */
public class TDOutHandler extends AbstractSoapInterceptor {

	private static final Logger logger = Log.getLogger(Log.SECURITY, TDOutHandler.class);

	private List<TrustDelegation> assertionList=null;

	private List<Element> assertionListDOM=null;
	private Element userAssertionDOM;

	private static final String phase=Phase.PRE_PROTOCOL;
	
	/**
	 * Add specified TD tokens into a header.
	 * User assertion won't be inserted. 
	 * @param tdChain Trust delegation tokens
	 */
	public TDOutHandler(List<TrustDelegation> tdChain)
	{
		super(phase);
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
		super(phase);
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
		super(phase);
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
		super(phase);
		init(tdChain, userCert, null, callerDN);
	}

	protected TDOutHandler()
	{
		super(phase);
		initHandler();
	}
	
	protected void initHandler()
	{
		getBefore().add(DSigOutHandler.class.getName());
		getBefore().add(SAAJOutInterceptor.class.getName());
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
		assertionListDOM = null;
		assertionList = (tdChain != null) ?
				tdChain : new ArrayList<TrustDelegation>();
		if (assertionList.size() != 0)
		{
			assertionListDOM = new ArrayList<Element>();
			try
			{
				for (TrustDelegation td: assertionList){
						Element el=DOMUtils.readXml(td.getXMLBeanDoc().newInputStream()).getDocumentElement();
						assertionListDOM.add(el);
				}
				logger.debug("Initialised TD Outhandler with " +
						"TD chain of length = " + assertionList.size());
			} catch(Exception e)
			{
				logger.warn("Can't create JDOM representation of TD assertion.",e);
				assertionListDOM = null;
			}
		}
		
		userAssertionDOM = null;
		if (userA != null)
		{
			try
			{
				AssertionDocument user = userA.getXMLBeanDoc();
				userAssertionDOM=DOMUtils.readXml(user.newInputStream()).getDocumentElement();
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

		if(SecuritySessionUtils.haveSessionID(message))
		{
			logger.debug("Skipping TD addition as security session is being used.");
			return;
		}
		if (assertionListDOM == null && userAssertionDOM == null)
		{
			logger.debug("Neither TD nor User assertion available.");
			return;
		}
		
		if(assertionListDOM != null && logger.isTraceEnabled())
		{
			logger.trace("TD DUMP begin");
			for(TrustDelegation td: assertionList)
				logger.trace(td.getXMLBeanDoc().toString());
			logger.trace("TD DUMP end");		
		}

		List<Header> h = message.getHeaders();
		Element insertionPoint = null;

		WSSecHeader sec = new WSSecHeader(true);
		insertionPoint = sec.getOrInsertWSSecElement(h);
		
		if (assertionListDOM != null)
		{
			for (Element e: assertionListDOM){
				Document parent=insertionPoint.getOwnerDocument();
				insertionPoint.appendChild(parent.importNode(e,true));
			}
		}
		if (userAssertionDOM != null)
		{
			Document parent=insertionPoint.getOwnerDocument();
			insertionPoint.appendChild(parent.importNode(userAssertionDOM,true));
			
			if (logger.isTraceEnabled()){
				try
				{
					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					DOMUtils.writeXml(userAssertionDOM, bos);
					logger.trace("User assertion:\n" + bos.toString());
				} catch(Exception e)
				{
					logger.warn("Can't output user assertion", e);
				}
			}
		}
	}
}
