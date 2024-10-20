/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <stdbool.h>
#include <sys/cdefs.h>

#include <cutils/multiuser.h>

#include <string>

__BEGIN_DECLS

// NOTE: keep in sync with StorageManager
static constexpr int FLAG_STORAGE_DE = 1 << 0;
static constexpr int FLAG_STORAGE_CE = 1 << 1;
// For 9.0 Ext4CryptPie.cpp
static constexpr int STORAGE_FLAG_DE = 1;
static constexpr int STORAGE_FLAG_CE = 2;

static constexpr int NAMESPACE_LOCKSETTINGS = 103;

namespace android {
namespace keystore {
    void copySqliteDb();
    int Get_Password_Type(const userid_t user_id, std::string& filename);
    bool Decrypt_DE();
    bool Decrypt_User(const userid_t user_id, const std::string& Password);
    bool Decrypt_Tied_User(userid_t user_id, userid_t parent_user_id);
}
}
__END_DECLS
