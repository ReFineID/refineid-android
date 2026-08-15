/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.keychain.external;

import android.os.IBinder;
import com.android.keychain.external.ExternalKeyProviderIdentity;
import com.android.keychain.external.ExternalKeyProviderResult;

/** Private Binder boundary shared by KeyChain and its statically trusted provider. */
@PermissionManuallyEnforced
interface IExternalKeyProviderService {
    const int PROTOCOL_VERSION = 1;

    int getProtocolVersion();

    ExternalKeyProviderIdentity getActiveIdentity();

    ExternalKeyProviderResult sign(
        int callerUid,
        in String[] callerPackages,
        String externalAlias,
        long providerGeneration,
        int algorithm,
        in byte[] digest,
        in IBinder operationToken);

    boolean removeIdentity(long providerGeneration);
}
