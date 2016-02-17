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
package org.wso2.carbon.context.api;

import org.wso2.carbon.context.api.internal.CarbonContextHolder;

import javax.security.auth.Subject;

/**
 * This provides the API for sub-tenant programming around Carbon based products. Each CarbonContext will utilize an
 * underlying {@link org.wso2.carbon.context.api.internal.CarbonContextHolder} instance, which will store the actual
 * data.
 *
 * @since 5.0.0
 */
public class CarbonContext {
    private CarbonContextHolder carbonContextHolder = null;

    protected CarbonContext(CarbonContextHolder carbonContextHolder) {
        this.carbonContextHolder = carbonContextHolder;
    }

    protected CarbonContextHolder getCarbonContextHolder() {
        return carbonContextHolder;
    }

    public static CarbonContext getThreadLocalCarbonContext() {
        return new CarbonContext(CarbonContextHolder.getThreadLocalCarbonContextHolder());
    }


    public String getTenantDomain() {
        return getCarbonContextHolder().getTenantDomain();
    }

    public Subject getSubject() {
        return getCarbonContextHolder().getSubject();
    }
}
