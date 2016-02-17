/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.wso2.carbon.axis2.runtime.internal;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.TransportInDescription;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.axis2.runtime.transport.DummyTransportListener;
import org.wso2.carbon.kernel.transports.CarbonTransport;
import org.wso2.carbon.messaging.CarbonMessageProcessor;

/**
 * Service component to consume CarbonTransport instance which has been registered as an OSGi service
 * by Carbon Kernel.
 *
 * @since 1.0.0
 */
@Component(
        name = "org.wso2.carbon.axis2.runtime.internal.CarbonAxis2Component",
        immediate = true
)
public class CarbonAxis2Component {
    private static final Logger logger = LoggerFactory.getLogger(CarbonAxis2Component.class);

    /**
     * This is the activation method of CarbonAxis2Component. This will be called when its references are
     * satisfied.
     *
     * @param bundleContext the bundle context instance of this bundle.
     * @throws Exception this will be thrown if an issue occurs while executing the activate method
     */
    @Activate
    protected void start(BundleContext bundleContext) throws Exception {
        logger.info("CarbonAxis2Component is activated");

        bundleContext.registerService(ConfigurationContext.class,
                DataHolder.getInstance().getConfigurationContext(), null);
        bundleContext.registerService(CarbonMessageProcessor.class, new Axis2CarbonMessageProcessor(), null);
    }

    /**
     * This is the deactivation method of CarbonAxis2Component. This will be called when this component
     * is being stopped or references are un-satisfied during runtime.
     *
     * @throws Exception this will be thrown if an issue occurs while executing the de-activate method
     */
    @Deactivate
    protected void stop() throws Exception {
        logger.info("CarbonAxis2Component is deactivated");
    }

    @Reference(
            name = "axis2-service-manager",
            service = AxisService.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeAxisService"
    )
    protected void addAxisService(AxisService axisService) {
        ConfigurationContext configurationContext = DataHolder.getInstance().getConfigurationContext();
        if (configurationContext != null) {
            try {
                configurationContext.deployService(axisService);
            } catch (AxisFault axisFault) {
                logger.error("Failed to deploy axis service : '{}'", axisService.getName(), axisFault);
            }
        }
    }

    protected void removeAxisService(AxisService axisService) {
        //TODO: Unregister service group + service form the Configuration Context
    }

    @Reference(
            name = "carbon-transport",
            service = CarbonTransport.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeCarbonTransport"
    )
    protected void addCarbonTransport(CarbonTransport carbonTransport) {
        ConfigurationContext configurationContext = DataHolder.getInstance().getConfigurationContext();
        if (configurationContext != null) {
            String transportId = carbonTransport.getId();
            TransportInDescription transportInDescription =
                    new TransportInDescription(transportId.substring(transportId.indexOf("-") + 1));
            transportInDescription.setReceiver(new DummyTransportListener());
            try {
                configurationContext.getAxisConfiguration().addTransportIn(transportInDescription);
                configurationContext.getListenerManager().addListener(transportInDescription, false);
            } catch (AxisFault axisFault) {
                logger.error("Error while configuring transport", axisFault);
            }
        }
    }

    protected void removeCarbonTransport(CarbonTransport carbonTransport) {
        try {
            DataHolder.getInstance().getConfigurationContext().getListenerManager().stop();
        } catch (AxisFault axisFault) {
            logger.error("Error while stopping transports", axisFault);
        }
    }
}
