package eu.unicore.security.xfireutil.client;

import org.apache.cxf.interceptor.LoggingOutInterceptor;


/**
 * logging handler that logs the full outgoing SOAP message at INFO level <br/>
 * 
 * @deprecated use CXF org.apache.cxf.interceptor.LoggingInInterceptor
 * @author schuller
 */
public class LogOutMessageHandler extends LoggingOutInterceptor {

}
