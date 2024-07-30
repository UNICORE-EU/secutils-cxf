package eu.unicore.security.wsutil;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.signature.XMLSignatureNodeInput;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * TODO this is a duplicate of the class from Samly,
 * slightly modified to work with xmlsec-4
 * 
 * it can be removed after samly is updated to xmlsec-4
 */
public class StandaloneCanonizer
{
	private DocumentBuilder documentBuilder;
	
	public StandaloneCanonizer() throws Exception
	{
		DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
		dfactory.setNamespaceAware(true);
		dfactory.setValidating(false);
		documentBuilder = dfactory.newDocumentBuilder();		
	}
	
	public static Element createDSctx(Document doc, String prefix, String namespace)
	{
		Element ctx = doc.createElementNS(null, "namespaceContext");
		ctx.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:" + prefix, namespace);
		return ctx;
	}


	public String fireCanon(Document inputDoc, boolean envSigTr) throws Exception
	{
		org.apache.xml.security.Init.init();
		XMLSignatureInput signatureInput = new XMLSignatureNodeInput((Node) inputDoc);
		Document transformDoc = documentBuilder.newDocument();
		XMLSignatureInput result;
		if (envSigTr)
		{
			Element nscontext = createDSctx(inputDoc, "ds", 
					Constants.SignatureSpecNS);
			Element transformsElement = (Element) XPathAPI.selectSingleNode(
					inputDoc, "//ds:Transforms", nscontext);
			Transforms transforms = new Transforms(transformsElement, 
					"memory://");
			result = transforms.performTransforms(signatureInput);
		} else
		{
			Transforms c14nTrans = new Transforms(transformDoc);
			transformDoc.appendChild(c14nTrans.getElement());
			c14nTrans.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
			result = c14nTrans.performTransforms(signatureInput);			
		}
		return new String(result.getBytes());
	}
}
