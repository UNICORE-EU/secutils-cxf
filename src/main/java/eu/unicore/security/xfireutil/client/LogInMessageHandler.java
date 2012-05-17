package eu.unicore.security.xfireutil.client;

import org.apache.cxf.interceptor.LoggingInInterceptor;

/**
 * logging handler that logs the full incoming SOAP message at INFO level<br/>
 * 
 * @deprecated use CXF org.apache.cxf.interceptor.LoggingInInterceptor
 * @author schuller
 */
public class LogInMessageHandler extends LoggingInInterceptor {

}
