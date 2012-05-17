package org.codehaus.xfire.util.stax;

import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.staxutils.W3CDOMStreamReader;
import org.w3c.dom.Attr;
import org.w3c.dom.CDATASection;
import org.w3c.dom.Comment;
import org.w3c.dom.Element;
import org.w3c.dom.EntityReference;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

/**
 * This implementation fixes bugs in the base class. Comments are properly handled.
 * Text content is not trimmed.
 * 
 * TODO is it still needed ?
 * 
 * @author K. Benedyczak
 */
public class W3CDOMStreamReader2 extends W3CDOMStreamReader
{
	private Node content;

	/**
	 * Get the text content of a node or null if there is no text
	 */
	public static String getContent(Node n)
	{
		if (n == null)
			return null;
		Node n1 = DOMUtils.getChild(n, Node.TEXT_NODE);
		if (n1 == null)
			return null;
		String s1 = n1.getNodeValue();
		return s1;
	}

	/**
	 * @param element
	 */
	public W3CDOMStreamReader2(Element element)
	{
		super(element);
	}

	protected int moveToChild(int currentChild)
	{
		this.content = getCurrentElement().getChildNodes().item(currentChild);

		if (content instanceof Text)
			return CHARACTERS;
		else if (content instanceof Element)
			return START_ELEMENT;
		else if (content instanceof CDATASection)
			return CDATA;
		else if (content instanceof Comment)
			return COMMENT;
		else if (content instanceof EntityReference)
			return ENTITY_REFERENCE;

		throw new IllegalStateException();
	}

	public String getAttributeValue(String ns, String local)
	{
		Attr at;
		if (ns == null || ns.equals(""))
			at = getCurrentElement().getAttributeNode(local);
		else
			at = getCurrentElement().getAttributeNodeNS(ns, local);

		if (at == null)
			return null;

		return getContent(at);
	}

	public String getText()
	{
		return content.getNodeValue();
	}
}
