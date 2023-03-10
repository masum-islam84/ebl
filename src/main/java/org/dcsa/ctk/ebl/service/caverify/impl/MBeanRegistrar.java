package org.dcsa.ctk.ebl.service.caverify.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import java.lang.management.ManagementFactory;
import java.util.Set;

public class MBeanRegistrar {

    private static final MBeanRegistrar ourInstance = new MBeanRegistrar();
    private static final Log log = LogFactory.getLog(MBeanRegistrar.class);

    public static MBeanRegistrar getInstance() {
        return ourInstance;
    }

    private MBeanRegistrar() {
    }

    public void registerMBean(Object mBeanInstance, String category, String id){
        assertNull(mBeanInstance, "MBean instance is null");
        assertNull(category, "MBean instance category is null");
        assertNull(id, "MBean instance name is null");
        try {
            MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
            ObjectName name = new ObjectName(getObjectName(category, id));
            Set set = mbs.queryNames(name, null);
            if (set != null && set.isEmpty()) {
                mbs.registerMBean(mBeanInstance, name);
            } else {
                mbs.unregisterMBean(name);
                mbs.registerMBean(mBeanInstance, name);
            }
        } catch (Exception e) {
            log.warn("Error registering a MBean with name ' " + id +
                    " ' and category name ' " + category + "' for JMX management", e);
        }
    }

    public void unRegisterMBean(String category, String id) {
        try {
            MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
            ObjectName objName = new ObjectName(getObjectName(category, id));
            if (mbs.isRegistered(objName)) {
                mbs.unregisterMBean(objName);
            }
        } catch (Exception e) {
            log.warn("Error un-registering a  MBean with name ' " + id +
                    " ' and category name ' " + category + "' for JMX management", e);
        }
    }

    private String getObjectName(String category, String id) {

        String jmxAgentName = System.getProperty("jmx.agent.name");
        if (jmxAgentName == null || "".equals(jmxAgentName)) {
            jmxAgentName = "org.apache.synapse";
        }
        return jmxAgentName + ":Type=" + category + ",Name=" + id;
    }

    private void assertNull(String name, String msg) {
        if (name == null || "".equals(name)) {
            handleException(msg);
        }
    }

    private void assertNull(Object object, String msg) {
        if (object == null) {
            handleException(msg);
        }
    }

    private static void handleException(String msg){
        log.error(msg);
        throw new RuntimeException(msg);
    }

}
