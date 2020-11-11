package eu.unicore.security.wsutil;


import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.phase.Phase;
import org.w3c.dom.Element;


/**
 * Checks if additional test element is present in WSS Security element. 
 * @author K. Benedyczak
 */
public class AdditionalInHandler extends AbstractSoapInterceptor
{
	public AdditionalInHandler()
	{
		super(Phase.PRE_INVOKE);
	}
	
	public void handleMessage(SoapMessage ctx)
	{
		buildDOM(ctx);
	}
	
	protected void buildDOM(SoapMessage msg) 
	{
		Element wsSecEl;
		WSSecHeader utilNoActor = new WSSecHeader(true);
		try
		{
			wsSecEl = utilNoActor.findWSSecElement(msg.getHeaders());
		} catch (Exception e)
		{
			return;
		}
		if (wsSecEl == null){
			return;
		}
		
		Element el =DOMUtils.getFirstChildWithName(wsSecEl, "http://test.org", "Tola");
		if (el != null){
			msg.put("tola", Boolean.TRUE);
		}
	}
}



