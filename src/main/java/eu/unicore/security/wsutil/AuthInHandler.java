/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.ICM file for licencing information.
 *
 * Created on May 31, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.namespace.QName;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.common.util.StringUtils;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Element;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AttributeStatementType;
import xmlbeans.org.oasis.saml2.assertion.AttributeType;
import xmlbeans.org.oasis.saml2.assertion.AuthnStatementType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.assertion.SubjectLocalityType;
import xmlbeans.org.oasis.saml2.assertion.SubjectType;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.FormatMode;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLBindings;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.trust.SamlTrustChecker;
import eu.unicore.samly2.validators.SSOAuthnAssertionValidator;
import eu.unicore.security.HTTPAuthNTokens;
import eu.unicore.security.SecurityTokens;
import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.UserAttributeHandler;
import eu.unicore.security.consignor.ConsignorAPI;
import eu.unicore.security.consignor.ConsignorAssertion;
import eu.unicore.security.user.UserAssertion;
import eu.unicore.security.wsutil.client.OAuthBearerTokenOutInterceptor;
import eu.unicore.util.Log;

/**
 * Security in-handler for UNICORE. Extracts consignor and user information
 * from the SOAP header.<br>
 * Processes three authN data sources:
 * <ul>
 *  <li>SAML Authentication assertions as an alternative way to authenticate the client
 *  <li>Consignor SAML assertions (produced by GW). It is assumed that the gw's assertion (if present)
 *  is the first assertion in the SOAP header.
 *  <li>As a fall back it can use certificates from the transport layer
 * </ul>
 * Note that all above sources of authN data can be turned off.
 * <p>
 * Additionally the following extra data is processed here:
 * <ul>
 *  <li>User SAML assertions (inserted by the consignor)
 *  <li>WSA Action (not really authN part but it is handy to do it here) 
 *  <li>HTTP auth data (Basic or OAuth2 Bearer token) is also extracted from the request.
 *  <li> client's IP
 * </ul>
 * <p>
 * The resulting data is feed into {@link SecurityTokens} class which is injected into 
 * request context. The raw tokens are populated along with user and consignor
 * fields.
 * <p>
 * NOTE: this handler must be invoked before handlers that relies on
 * authentication data, so make sure to invoke <br>
 * <code> after(AuthNInHandler.class.getName());</code><br>
 * in the constructor of any such handler.
 * <p>
 * WARNING: Never use this handler without consignor assertions verification turned on,
 * when access to the service is possible not exclusively through the gataway (i.e. the 
 * service is not protected by firewall)! Doing so effectively turns off the whole authentication,
 * as anyone can attach a fake "gateway" assertion in her/his request.
 * <p>
 * WARNING: This class doesn't verify neither the certificate obtained from the transport layer nor
 * from Consignor's assertion (gateway should verify them). 
 * Therefore the HTTPS server must be properly configured to verify clients if usage of SSL data is turned on.  
 * 
 * @author K. Benedyczak
 */
public class AuthInHandler extends AbstractSoapInterceptor
{
	protected static final Logger logger = Log.getLogger(Log.SECURITY, AuthInHandler.class);
	
	public static final String SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
	/**
	 * Under this key in the context of SecurityTokens all saml assertions that were not consumed by
	 * this handler will be stored. So all assertions except Consignor and User.
	 */
	public static final String RAW_SAML_ASSERTIONS_KEY = AuthInHandler.class.getName() + 
			".RAW_SAML_ASSERTIONS";

	// special header for forwarding the client's IP address to the VSite
	public final static String CONSIGNOR_IP_HEADER = "X-UNICORE-Consignor-IP";
		
	private final boolean useGatewayAssertions;
	private final boolean useHTTPBasic;
	private final boolean useSSLData;
	private final X509Certificate gatewayC;
	private final boolean verifyConsignor;
	private SamlTrustChecker samlAuthnTrustChecker;
	private String samlConsumerName;
	private String samlConsumerEndpointUri;
	private long samlGraceTime;
	
	private final String actor;

	private final List<UserAttributeHandler> userAttributeHandlers = new ArrayList<UserAttributeHandler>();
	
	private final Set<QName>qnameSet=new HashSet<QName>();
	
	private final SecuritySessionStore sessionStore;
	
	/**
	 * Constructs instance of the handler. It will accept assertions in the header element
	 * without the actor set. Note that by default out handlers do not set the actor so
	 * this version should be used in most cases.
	 * @param useGatewayAssertions if true then consignor assertions from gateway 
	 * will be honored.
	 * @param useSSLData if true and no valid assertion from gateway is found then
	 * SSL/TLS certificates will be tried.
	 * @param extractHTTPData if true then HTTP Basic Auth data will be extracted and
	 * injected into context.
	 * @param gatewayC if not null then consignor assertions will be verified. This
	 * make sense only when useGatewayAssertions is true otherwise is ignored.
	 * @param sessionStore security session storage
	 */
	public AuthInHandler(boolean useGatewayAssertions, boolean useSSLData,
			boolean extractHTTPData, X509Certificate gatewayC, SecuritySessionStore sessionStore)
	{
		this(useGatewayAssertions, useSSLData, extractHTTPData, gatewayC, null, sessionStore);
	}

	/**
	 * Constructs instance of the handler.
	 * @param useGatewayAssertions if true then consignor/user assertions from gateway 
	 * will be honored.
	 * @param useSSLData if true and no valid assertion from gateway is found then
	 * SSL/TLS certificates will be tried.
	 * @param extractHTTPData if true then HTTP Basic Auth data will be extracted and
	 * injected into context.
	 * @param gatewayC if not null then consignor assertions will be verified. This
	 * make sense only when useGatewayAssertions is true otherwise is ignored.
	 * @param actor Name of this service as used in WSSecurity actor field.
	 * @param sessionStore security session storage
	 */
	public AuthInHandler(boolean useGatewayAssertions, boolean useSSLData,
			boolean extractHTTPData, X509Certificate gatewayC, String actor,
			SecuritySessionStore sessionStore)
	{
		super(Phase.PRE_INVOKE);
		qnameSet.add(new QName(WSSecHeader.WSSE_NS_URI,WSSecHeader.WSSE_LN));

		this.useGatewayAssertions = useGatewayAssertions;
		this.useHTTPBasic = extractHTTPData;
		this.useSSLData = useSSLData;
		if (gatewayC != null && useGatewayAssertions)
		{
			this.gatewayC = gatewayC;
			verifyConsignor = true;
		}
		else{
			this.gatewayC = null;
			verifyConsignor = false;
		}
		this.actor = actor;
		this.sessionStore = sessionStore;
	}

	public void enableSamlAuthentication(String consumerSamlName, String consumerEndpointUri, 
			SamlTrustChecker samlTrustChecker, long samlValidityGraceTime)
	{
		this.samlAuthnTrustChecker = samlTrustChecker;
		this.samlConsumerEndpointUri = consumerEndpointUri;
		this.samlConsumerName = consumerSamlName;
		this.samlGraceTime = samlValidityGraceTime;
	}
	
	public void disableSamlAuthentication()
	{
		this.samlAuthnTrustChecker = null;
	}
	
	
	public void addUserAttributeHandler(UserAttributeHandler uh){
		userAttributeHandlers.add(uh);
	}
	
	@Override
	public Set<QName> getUnderstoodHeaders()
	{
		return qnameSet;
	}

	@Override
	public void handleMessage(SoapMessage ctx)
	{
		String sessionID=SecuritySessionCreateInHandler.getSecuritySessionID(ctx);
		SecurityTokens mainToken;
		if (sessionID==null)
		{
			mainToken = new SecurityTokens();
			process(ctx, mainToken);
		} else {
			// re-using session
			SecuritySession session = getSession(ctx, sessionID);
			mainToken = session.getTokens();
			mainToken.getContext().put(SecuritySessionUtils.REUSED_MARKER_KEY, Boolean.TRUE);
			// make sure session info goes to the client
			SessionIDServerOutHandler.setSession(session);
			if(logger.isDebugEnabled()){
				logger.debug("Re-using session "+sessionID+" for <"+session.getUserKey()+">");
			}
		}
		ctx.put(SecurityTokens.KEY, mainToken);
	}

	/**
	 * get the stored session
	 *  
	 * @param message
	 * @param sessionID
	 * @return
	 */
	protected SecuritySession getSession(SoapMessage message, String sessionID){
		SecuritySession session = null;
		session=sessionStore.getSession(sessionID);
		if (session==null || session.isExpired()){
			// got a session ID from the client, but no session: fault
			throwFault(432, "No (valid) security session found, please (re-)send full security data!");
		}
		return session;
	}
	
	/**
	 * process AuthN info from the message and put it into the SecurityToken 
	 * @param ctx -incoming message
	 * @param mainToken - security tokens for this request
	 */
	protected void process(SoapMessage ctx, SecurityTokens mainToken){

		if (useHTTPBasic)
		{
			HTTPAuthNTokens fromHttp = getHTTPCredentials(ctx);
			if (fromHttp != null)
			{
				mainToken.getContext().put(
						SecurityTokens.CTX_LOGIN_HTTP, fromHttp);
			}
			// OAuth token
			String bearer = CXFUtils.getBearerToken(ctx);
			if(bearer != null){
				if(logger.isDebugEnabled())logger.debug("Have OAuth bearer token.");
				mainToken.getContext().put(OAuthBearerTokenOutInterceptor.TOKEN_KEY, bearer);
			}
		}

		ConsignorAssertion cAssertion = null;
		Element uAssertion = null;
		Element samlAuthnAssertion = null;
		if (ctx.hasHeaders())
		{
			List<Element> assertions = extractSAMLAssertions(ctx);

			if (useGatewayAssertions)
				cAssertion = getConsignorAssertion(assertions);
			uAssertion = getUserAssertion(assertions);
			samlAuthnAssertion = getSAMLAuthnAssertion(assertions);
			mainToken.getContext().put(RAW_SAML_ASSERTIONS_KEY, assertions);
		}

		if (samlAuthnTrustChecker != null && samlAuthnAssertion != null)
			processSAMLAuthentication(samlAuthnAssertion, cAssertion, mainToken, ctx);
		else
		{
			if (samlAuthnAssertion != null)
			{
				throwFault(400, "Got request with SAML Authentication assertions, but " +
						"this server does not allow for SAML authentication.");
			}
				
			processConsignor(cAssertion, mainToken, ctx);
		}

		if (uAssertion != null)
		{
			try{
				processUser(uAssertion, mainToken);
			}catch(IOException i){
				throw new Fault(i);
			}
		}

		mainToken.getContext().put(SecurityTokens.CTX_SCOPE_KEY, 
				SecurityTokens.SCOPE_REQUEST);			
		mainToken.getContext().put(SecurityTokens.CTX_SOAP_ACTION, 
				getSOAPAction(ctx));
	}
	
	protected List<Element> extractSAMLAssertions(SoapMessage message)
	{
		List<Header> headers=message.getHeaders();
		List<Element> assertions = new ArrayList<Element>();
		
		if (headers.size()==0)
		{
			logger.debug("No SOAP header");
			return assertions;
		} 

		Element wsSecEl = null;
		if (actor != null)
		{
			WSSecHeader utilActor = new WSSecHeader(actor, true);
			wsSecEl = utilActor.findWSSecElement(headers);
		}
		if (wsSecEl == null)
		{
			WSSecHeader utilNoActor = new WSSecHeader(true);
			wsSecEl = utilNoActor.findWSSecElement(headers);
		}

		
		//This list can contain GW consignor assertion and also other ones inserted by 
		//older clients (new clients should insert assertions under wssec:Security element)
		
		List<Element> directAssertions = new ArrayList<Element>();
		for(Header h: headers){
			if(SAML2_NS.equals(h.getName().getNamespaceURI()) && "Assertion".equals(h.getName().getLocalPart())){
				directAssertions.add((Element)h.getObject());
			}
		}
		assertions.addAll(directAssertions);
		
		if (wsSecEl != null)
		{
			assertions.addAll(DOMUtils.getChildrenWithName(wsSecEl, SAML2_NS, "Assertion"));
			if (assertions.size() == 0)
				logger.debug("No assertion found in the wssec:Security element");
		} else
			logger.debug("No valid WS Security element found in SOAP header");
		return assertions;
	}

	protected void processUser(Element uAssertion, SecurityTokens mainToken) throws IOException
	{
		logger.debug("Found user assertion in request");
		UserAssertion userA = processUserAssertion(uAssertion);
		X509Certificate[] user = extractCertPath(userA);
		if (user == null)
		{
			String userName = userA.getSubjectName();
			mainToken.setUserName(userName);
			if (logger.isDebugEnabled())
				logger.debug("Requested USER (retrieved as a DN): " + 
						X500NameUtils.getReadableForm(userName));
		} else
		{
			mainToken.setUser(user);
			if (logger.isDebugEnabled())
				logger.debug("Requested USER (retrieved as a full certificate): " +
						CertificateUtils.format(
							user[0], FormatMode.COMPACT_ONE_LINE));
		}

		//extract any additional attributes and process them
		AttributeStatementType[] attributes=userA.getXMLBean().getAttributeStatementArray();
		if( attributes!=null && userAttributeHandlers.size()>0){
			for(AttributeStatementType attrStatement: attributes){
				for(AttributeType attr: attrStatement.getAttributeArray()){
					String nameFormat=attr.getNameFormat();
					if(UserAssertion.ROLE_NAME_FORMAT.equals(nameFormat))continue;
					String name=attr.getName();
					XmlObject[] values=attr.getAttributeValueArray();
					for(UserAttributeHandler h: userAttributeHandlers){
						h.processUserDefinedAttribute(name, nameFormat, values, mainToken);
					}
				}
			}
		}

	}

	protected void processSAMLAuthentication(Element samlAuthnAssertion, ConsignorAssertion cAssertion, 
			SecurityTokens mainToken, SoapMessage message)
	{
		SSOAuthnAssertionValidator validator = new SSOAuthnAssertionValidator(samlConsumerName, 
				samlConsumerEndpointUri, null, samlGraceTime, samlAuthnTrustChecker, null, 
				SAMLBindings.OTHER);
		validator.setLaxInResponseToChecking(true);
		validator.addConsumerSamlNameAlias(samlConsumerEndpointUri);
		AssertionDocument assertionDoc;
		try
		{
			assertionDoc = AssertionDocument.Factory.parse(samlAuthnAssertion);
		} catch (XmlException e1)
		{
			Log.logException("SAML authentication assertion received in request can " +
					"not be parsed", e1, logger);
			throwFault(400, "SAML authentication assertion received in request can " +
					"not be parsed " + e1.toString());
			return;//dummy
		}
		
		try
		{
			validator.validate(assertionDoc);
		} catch (SAMLValidationException e1)
		{
			logger.warn("SAML authentication assertion received in request is " +
					"not trusted: " + e1.getMessage());
			throwFault(400, "SAML authentication assertion received in request can " +
					"not be parsed " + e1.getMessage());
		}
		
		SubjectType subject = assertionDoc.getAssertion().getSubject();
		NameIDType subjectName = subject.getNameID();
		if (subjectName == null)
			throwFault(400, "SAML authentication for UNICORE assertion must have nameID element");
		if (!SAMLConstants.NFORMAT_DN.equals(subjectName.getFormat()))
			throwFault(400, "SAML authentication assertion for UNICORE must have subject of " + 
					SAMLConstants.NFORMAT_DN + " format, was: " + subjectName.getFormat());
		String consignorDn = subjectName.getStringValue();
		if (consignorDn == null || consignorDn.isEmpty())
			throwFault(400, "SAML authenticated user must be non-empty");
		String readableDn;
		try
		{
			readableDn = X500NameUtils.getReadableForm(consignorDn);
			logger.debug("Using consignor info from SAML authentication assertion: " + readableDn);
		} catch (Exception e)
		{
			Log.logException("Invalid DN in SAML authn assertion", e, logger);
			throwFault(400, "SAML authenticated user identity is not a valid X.500 name: " + e.toString());
		}
		mainToken.setConsignorName(consignorDn);
		establishIP(cAssertion, mainToken, message);
	}	

	
	protected void processConsignor(ConsignorAssertion cAssertion, SecurityTokens mainToken, SoapMessage message)
	{
		if (cAssertion == null && useGatewayAssertions)
			logger.debug("No consignor info in request -> " +
			"request didn't come through a gateway");
		X509Certificate[] consignor = null;
		String clientIP = null;
		
		if (cAssertion != null && useGatewayAssertions)
		{
			consignor = processConsignorAssertion(cAssertion);
			if (consignor != null){
				logger.debug("Using consignor info from Gateway.");
				clientIP = extractIPFromConsignorAssertion(cAssertion);
			}
		}

		if (cAssertion == null && useSSLData)
		{
			consignor = getSSLCertPath(message);
			clientIP = getClientIP(message);
			if (consignor != null)
				logger.debug("Using consignor info from SSL connection.");
		}

		if (logger.isDebugEnabled() && consignor != null)
			logger.debug("Consignor: " + X500NameUtils.getReadableForm(
					consignor[0].getSubjectX500Principal()));
		if (consignor == null)
			logger.debug("No valid Consignor info received, request is not authenticated.");
		else
			mainToken.setConsignor(consignor);
		
		mainToken.setClientIP(clientIP);
	}	

	/**
	 * Sets a client IP in the security tokens. The IP is taken either from ConsignorAssertion
	 * (if present, valid and we are configured to use them) or from the transport layer otherwise.
	 * @param cAssertion
	 * @param mainToken
	 * @param message
	 */
	protected void establishIP(ConsignorAssertion cAssertion, SecurityTokens mainToken, SoapMessage message)
	{
		String clientIP = null;
		if (cAssertion != null && useGatewayAssertions)
		{
			X509Certificate[] consignor = processConsignorAssertion(cAssertion);
			if (consignor != null){
				logger.debug("Using consignor info from Gateway.");
				clientIP = extractIPFromConsignorAssertion(cAssertion);
			}
		}
		
		if(clientIP == null)
		{
			// see if we have the special Gateway header
			String ip = CXFUtils.getServletRequest(message).getHeader(CONSIGNOR_IP_HEADER);
			clientIP = ip!=null? ip : getClientIP(message);
		}
		mainToken.setClientIP(clientIP);
	}
	
	protected X509Certificate[] getSSLCertPath(SoapMessage message)
	{
		return CXFUtils.getSSLCerts(message);
	}

	protected String getClientIP(SoapMessage message)
	{
		return CXFUtils.getClientIP(message);
	}

	protected String extractIPFromConsignorAssertion(ConsignorAssertion cAssertion)
	{
		AuthnStatementType[] authNs = cAssertion.getXMLBean().getAuthnStatementArray();
		if (authNs == null || authNs.length == 0)
			return null;
		SubjectLocalityType loc = authNs[0].getSubjectLocality();
		if (loc == null)
			return null;
		return loc.getAddress();
	}

	protected HTTPAuthNTokens getHTTPCredentials(SoapMessage message)
	{
		return CXFUtils.getHTTPCredentials(message);
	}

	protected Element getUserAssertion(List<Element> assertions)
	{
		for (int i=assertions.size()-1; i>=0; i--)
		{
			Element a = (Element) assertions.get(i);
			List<Element> ass=DOMUtils.getChildrenWithName(a, SAML2_NS, "AttributeStatement");
			if(ass.size()==0)continue;
			Element as = ass.get(0);
			if (as == null) continue;
			
			List<Element> attrs = DOMUtils.getChildrenWithName(as, SAML2_NS, "Attribute");
			for (Element attr: attrs)
			{
				String a1 = attr.getAttribute("Name");
				String a2 = attr.getAttribute("NameFormat");
				if (StringUtils.isEmpty(a1)|| StringUtils.isEmpty(a2))
					continue;

				if (a1.equals("USER") && a2.equals("urn:unicore:subject-role"))
				{
					assertions.remove(i);
					return a;
				}
			}

		}
		return null;
	}

	protected Element getSAMLAuthnAssertion(List<Element> assertions)
	{
		Element ret = null;
		for (int i=assertions.size()-1; i>=0; i--)
		{
			Element a = (Element) assertions.get(i);
			List<Element> ass=DOMUtils.getChildrenWithName(a, SAML2_NS, "AuthnStatement");
			if(ass.size()==0)continue;
			Element as = ass.get(0);
			if (as == null) continue;
			if (ret != null)
				throwFault(400, "Multiple SAML authentication assertions received, " +
						"what is not supported.");
			ret = a;
			assertions.remove(i);
		}
		return ret;
	}

	
	/**
	 * Returns parsed but not verified in any way consignor assertion. The
	 * first assertion is tried and returned if looks like consignor i.e. has a proper
	 * attribute tag.
	 * @param assertions
	 * @return
	 */
	protected ConsignorAssertion getConsignorAssertion(List<Element> assertions)
	{
		if (assertions.size() == 0) 
			return null;
		
		try
		{
			ByteArrayOutputStream os=new ByteArrayOutputStream();
			CXFUtils.writeXml(assertions.get(0), os);
			AssertionDocument aDoc = AssertionDocument.Factory.parse(os.toString());
			ConsignorAssertion ca = new ConsignorAssertion(aDoc);
			assertions.remove(0);
			return ca;
		} catch (Exception e)
		{
			logger.debug("The first assertion is not a valid CONSIGNOR " +
					"assertion, ignoring: "	+ e.getMessage());
			return null;
		}
	}

	protected X509Certificate[] processConsignorAssertion(ConsignorAssertion consignorA)
	{
		X509Certificate[] cert = consignorA.getConsignor();
		if (verifyConsignor)
		{
			if (!consignorA.isSigned())
			{
				logger.warn("Consignor assertion is "
						+ "unsigned. Probably gateway is not "
						+ "configured properly to sign consignor"
						+ " assertions. Either fix gateway "
						+ "configuration or turn off signature "
						+ "checking in this server's configuration");
				return null;
			}
			ConsignorAPI engine = UnicoreSecurityFactory.getConsignorAPI();
			eu.unicore.security.ValidationResult res = engine.verifyConsignorToken(
					consignorA, gatewayC);
			if (!res.isValid())
			{
				String subject = (cert == null || cert.length == 0) ? "null" : 
					X500NameUtils.getReadableForm(cert[0].getSubjectX500Principal());
				logger.warn("Consignor assertion is "
						+ "invalid (probably FAKED): "
						+ res.getInvalidResaon()
						+ ", inserted consignor was: "
						+ subject);
				return null;
			}
			logger.debug("Successfully verified consignor assertion.");
		}

		if (cert == null)
			logger.debug("Anonymous CONSIGNOR");
		return cert;
	}

	protected UserAssertion processUserAssertion(Element assertion)
	{
		UserAssertion userA;
		try
		{
			ByteArrayOutputStream os=new ByteArrayOutputStream();
			StaxUtils.writeTo(assertion, os);
			AssertionDocument aDoc = AssertionDocument.Factory.parse(os.toString());
			userA = new UserAssertion(aDoc);
			return userA;
		} catch (Exception e)
		{
			logger.warn("The USER assertion is invalid, ignoring: "
					+ e.getMessage());
			return null;
		}
	}	

	protected X509Certificate[] extractCertPath(UserAssertion userA)
	{
		X509Certificate[] cert = userA.getSubjectFromConfirmation();
		if (cert == null)
			logger.debug("USER retrieved, but no certificate is given.");
		return cert;
	}

	protected String getSOAPAction(SoapMessage message){
		String action=CXFUtils.getAction(message);
				
		if (logger.isDebugEnabled() && action != null){
			logger.debug("Setting SOAP action to '" + action + "'");
		}
		return action;
	}

	
	protected void throwFault(int httpErrorCode, String message)
	{
		logger.debug("AuthN failed: " + message);
		Fault f = new Fault((Throwable)null); // null is OK
		f.setStatusCode(httpErrorCode); // unassigned according to IANA ;)
		f.setMessage(message);
		throw f;
	}
}
