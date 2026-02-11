package eu.unicore.security.wsutil.cxf;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.apache.cxf.databinding.AbstractWrapperHelper;
import org.apache.xmlbeans.XmlOptions;


public class XmlBeansWrapperHelper extends AbstractWrapperHelper {
    
    public XmlBeansWrapperHelper(Class<?> wt, Method[] sets, Method[] gets, Field[] f) {
        super(wt, sets, gets, f);
       
    }

    @Override
    protected Object createWrapperObject(Class<?> typeClass) throws Exception {
        Class<?> cls[] = typeClass.getDeclaredClasses();
        Method newType = null;
        for (Method method : typeClass.getMethods()) {
            if (method.getName().startsWith("addNew")) {
                newType = method;
                break;
            }
        }                     
        Object obj = null;
        for (Class<?> c : cls) {                        
            if ("Factory".equals(c.getSimpleName())) {
                if (validate) {
                    // set the validation option here
                    Method method = c.getMethod("newInstance", XmlOptions.class); 
                    XmlOptions options = new XmlOptions();                    
                    options.setValidateOnSet();                    
                    obj = method.invoke(null, options);
                } else {
                    Method method = c.getMethod("newInstance", NO_CLASSES);
                    obj = method.invoke(null, NO_PARAMS);                    
                }
                if (newType != null) {
                    // create the value object
                    obj = newType.invoke(obj, NO_PARAMS);
                }
                break;
            }
        }
        
        return obj;
    }

    @Override
    protected Object getWrapperObject(Object object) throws Exception {                            
        Method m = getXMLBeansValueMethod(wrapperType);
        Method method = null;
        if (m == null) {
            Class<?> valueClass = getXMLBeansValueType(wrapperType);
            // we need get the real Object first
            method = wrapperType.getMethod("get" + valueClass.getSimpleName(), NO_CLASSES);
        } else {
            method = wrapperType.getMethod("get" + m.getName().substring(6), NO_CLASSES);
        }
        return method.invoke(object, NO_PARAMS);
    }
    public static Method getXMLBeansValueMethod(Class<?> wrapperType)  {
        for (Method method : wrapperType.getMethods()) {
            if (method.getName().startsWith("addNew")) {                
                return method;
            }
        }
        return null;
    }

    public static Class<?> getXMLBeansValueType(Class<?> wrapperType)  {
        Class<?> result = wrapperType;
        for (Method method : wrapperType.getMethods()) {
            if (method.getName().startsWith("addNew")) {                
                result = method.getReturnType();
                break;
            }
        }
        return result;
    }

}
