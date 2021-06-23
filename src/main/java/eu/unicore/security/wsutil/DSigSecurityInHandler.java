package eu.unicore.security.wsutil;


import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.namespace.QName;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.phase.Phase;
import org.apache.logging.log4j.Logger;
import org.apache.wss4j.common.WSEncryptionPart;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.unicore.security.SecurityTokens;
import eu.unicore.security.SignatureStatus;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.DigSignatureUtil;
import eu.unicore.security.dsig.IdAttribute;
import eu.unicore.security.wsutil.client.ToBeSignedDecider;
import eu.unicore.util.Log;


/**
 * Checks if there is signature in the SOAP header. If it is present then it is
 * verified with CONSIGNOR certificate (i.e. the consignor certificate MUST be the
 * same as digital signature creator).</br>
 * 
 * According to the verification result is saved in   
 * the security tokens.</br>
 * 
 * <p>
 * This handler must be AFTER {@link AuthInHandler} handler that sets consignor 
 * into security context and AFTER {@link DSigParseInHandler}
 * <p>
 * The signature is searched only if the DOM of the message was build by the 
 * {@link DSigParseInHandler}.
 *
 * @see SecurityTokens
 * @author K. Benedyczak
 */
public class DSigSecurityInHandler extends AbstractSoapInterceptor
{
	private static Logger logger = Log.getLogger(Log.SECURITY + ".dsig",
			DSigSecurityInHandler.class);

	private static final String WSS_NS_STRING = "http://docs.oasis-open.org/wss/2004/01/" +
			"oasis-200401-wss-wssecurity-secext-1.0.xsd"; 

	private static final String XML_DS_STRING = "http://www.w3.org/2000/09/xmldsig#";

	public static final QName WS_SECURITY=new QName(WSS_NS_STRING,"Security");

	private static final String WSSUTIL_NS_STRING = 
			"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
	public static final IdAttribute WS_ID_ATTRIBUTE=new IdAttribute(WSSUTIL_NS_STRING, "Id");

	private ToBeSignedDecider partsDecider;

	private final static Set<QName>qnameSet=new HashSet<QName>();
	static{
		qnameSet.add(WS_SECURITY);
	}

	public DSigSecurityInHandler(ToBeSignedDecider partsDecider)
	{
		super(Phase.PRE_INVOKE);
		getAfter().add(DSigParseInHandler.class.getName());
		getAfter().add(AuthInHandler.class.getName());
		this.partsDecider = partsDecider;
	}

	@Override
	public Set<QName> getUnderstoodHeaders() {
		return qnameSet;
	}


	public void handleMessage(SoapMessage message) 
	{
		SecurityTokens securityTokens = (SecurityTokens) message.get(SecurityTokens.KEY);
		if (securityTokens == null)
		{
			logger.error("No security context found. You should add " + 
					AuthInHandler.class.getName() + " handler.");
			return;
		}
		
		securityTokens.setMessageSignatureStatus(SignatureStatus.UNCHECKED);
		Document doc = (Document) message.get(DSigParseInHandler.DOCUMENT_DOM_KEY);
		if (doc == null)
		{
			logger.debug("No DOM representation of message found, signature won't be checked");
			return;
		}

		Header wssHeader = message.getHeader(WS_SECURITY);

		if (wssHeader == null)
		{
			logger.debug("No security header element found, skipping signature verification.");
			securityTokens.setMessageSignatureStatus(SignatureStatus.UNSIGNED);
			return;
		}

		Element secHeader = (Element)wssHeader.getObject();
		
		if (getChildElements(secHeader,XML_DS_STRING,"Signature").size()==0)
		{
			logger.debug("No Signature was found in header, skipping signature verification.");
			securityTokens.setMessageSignatureStatus(SignatureStatus.UNSIGNED);
			return;
		}

		try
		{
			verify(securityTokens, doc, secHeader);
		} catch (Exception e)
		{
			logger.warn("Error while checking signature of request: ", e);
			securityTokens.setMessageSignatureStatus(SignatureStatus.WRONG);
			return;
		}

	}

	/**
	 * @param securityTokens
	 * @param doc DOM document
	 * @param secHeader WS-Security header INCLUDING signature
	 * @throws Exception
	 */
	protected void verify(SecurityTokens securityTokens, Document doc, Element secHeader)throws Exception{
		long start = System.currentTimeMillis();

		X509Certificate[] consignorCC = securityTokens.getConsignor();
		if (consignorCC == null || consignorCC.length == 0)
		{
			logger.debug("No consignor found in security context so skipping signature verification.");
			return;
		}
		X509Certificate consignorCert = consignorCC[0];
		//we trust that consignor was properly verified by GW or transport layer
		PublicKey consignorsKey = consignorCert.getPublicKey();

		long preVerify = System.currentTimeMillis();
		boolean signedOK;
		try
		{
			logger.trace("Starting signature verification");
			signedOK = verifySignature(doc, consignorsKey);
		} catch (Exception e)
		{
			logger.warn("Error while checking signature of request: ", e);
			securityTokens.setMessageSignatureStatus(SignatureStatus.WRONG);
			return;
		}
		if (signedOK)
		{
			logger.debug("Signature present and CORRECT");
			securityTokens.setMessageSignatureStatus(SignatureStatus.OK);
		} else
		{
			logger.warn("Signature present but INCORRECT!!");
			securityTokens.setMessageSignatureStatus(SignatureStatus.WRONG);
		}
		long end = System.currentTimeMillis();
		logger.debug("Total time: {} where actual verification was: {}", (end-start), (end-preVerify));
	}

	private boolean verifySignature(Document signedDocument, PublicKey validatingKey) 
			throws DSigException
			{
		NodeList nl = signedDocument.getElementsByTagNameNS(
				WSS_NS_STRING, "Security");
		if (nl.getLength() == 0)
			throw new DSigException("Document not signed");
		if (nl.getLength() > 1)
			throw new DSigException("Document contains more then one wss:Security element. This is not supported and may indicate an attack on XML digital signature.");
		org.w3c.dom.Element securityElement = (org.w3c.dom.Element) nl.item(0);

		List<org.w3c.dom.Element> signatures = getChildElements(securityElement, XMLSignature.XMLNS, "Signature");
		if (signatures.size() == 0)
			throw new DSigException("Document not signed");
		if (signatures.size() > 1)
			throw new DSigException("Document's wss:Security element contains more then one dsig:Signature element. This is not supported and may indicate an attack on XML digital signature.");
		DigSignatureUtil dsigEngine = new DigSignatureUtil();
		Node signatureNode = signatures.get(0);
		List<org.w3c.dom.Element> required = getRequiredElements(signedDocument);

		return dsigEngine.verifyDetachedSignature(signedDocument, required, WS_ID_ATTRIBUTE, 
				validatingKey, signatureNode);
			}

	private List<org.w3c.dom.Element> getChildElements(org.w3c.dom.Element from, String ns, String localName)
	{
		List<org.w3c.dom.Element> ret = new ArrayList<org.w3c.dom.Element>();
		NodeList children = from.getChildNodes();
		for (int i=0; i<children.getLength(); i++)
		{
			Node child = children.item(i);
			if (!(child instanceof org.w3c.dom.Element))
				continue;
			org.w3c.dom.Element childE = (org.w3c.dom.Element) child;
			if (localName.equals(childE.getLocalName()) && ns.equals(childE.getNamespaceURI()))
				ret.add(childE);
		}
		return ret;
	}

	/**
	 * @param signedDocument
	 * @return a list of DOM elements which should be signed according to our policy. If policy
	 * is not set only the Body element is returned.
	 */
	private List<org.w3c.dom.Element> getRequiredElements(Document signedDocument)
	{
		Vector<WSEncryptionPart> shallBeSigned;
		if (partsDecider != null)
			shallBeSigned = partsDecider.getElementsToBeSigned(signedDocument);
		else
		{
			shallBeSigned = new Vector<WSEncryptionPart>();
			shallBeSigned.add(new WSEncryptionPart("Body",
					"http://schemas.xmlsoap.org/soap/envelope/", ""));
		}
		List<org.w3c.dom.Element> ret = new ArrayList<org.w3c.dom.Element>();
		for (WSEncryptionPart part: shallBeSigned)
		{
			logger.trace("Required part: {}", part.getName());
			NodeList nl = signedDocument.getElementsByTagNameNS(
					part.getNamespace(), part.getName());
			//no such element in document so it can't be signed.
			if (nl.getLength() == 0)
				continue;
			//The node list can contain more then 1 element.
			//We check if every one of them is signed.
			for (int i=0; i<nl.getLength(); i++)
				ret.add((org.w3c.dom.Element)nl.item(i));
		}
		return ret;
	}

}



