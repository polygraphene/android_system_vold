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

#include <array>

#include <asm/ioctl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <cutils/properties.h>
#include <logwrap/logwrap.h>
#include <utils/misc.h>
#include <fscrypt/fscrypt.h>
#include "KeyUtil.h"

#include "fscrypt_policy.h"

static int encryption_mode = FS_ENCRYPTION_MODE_PRIVATE;

bool fscrypt_is_native() {
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.crypto.type", value, "none");
    return !strcmp(value, "file");
}

extern "C" void bytes_to_hex(const uint8_t *bytes, size_t num_bytes, char *hex) {
  for (size_t i = 0; i < num_bytes; i++) {
    sprintf(&hex[2 * i], "%02x", bytes[i]);
  }
}

extern "C" bool fscrypt_set_mode() {
    const char* mode_file = "/data/unencrypted/mode";
    struct stat st;
    if (stat(mode_file, &st) != 0 || st.st_size <= 0) {
        printf("Invalid encryption mode file %s\n", mode_file);
        return false;
    }
    ssize_t mode_size = st.st_size;
    char contents_encryption_mode[mode_size + 1];
    memset((void*)contents_encryption_mode, 0, mode_size + 1);
    int fd = open(mode_file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("error opening '%s': %s\n", mode_file, strerror(errno));
        return false;
    }
    if (read(fd, contents_encryption_mode, mode_size) != mode_size) {
        printf("read error on '%s': %s\n", mode_file, strerror(errno));
        close(fd);
        return false;
    }
    close(fd);

    std::string contents_encryption_mode_string = std::string(contents_encryption_mode);
    int pos = contents_encryption_mode_string.find(":");
    LOG(INFO) << "contents_encryption_mode_string: " << contents_encryption_mode_string.substr(0, pos);

    if (contents_encryption_mode_string.substr(0, pos) == "software") {
        encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS;
    } else if (contents_encryption_mode_string.substr(0, pos) == "ice") {
        encryption_mode = FS_ENCRYPTION_MODE_PRIVATE;
    } else {
        printf("Invalid encryption mode '%s'\n", contents_encryption_mode);
        return false;
    }

    printf("set encryption mode to %i\n", encryption_mode);
    return true;
}

extern "C" bool fscrypt_policy_set_struct(const char *directory, fscrypt_policy *fep) {
    int fd = open(directory, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        printf("failed to open %s\n", directory);
        PLOG(ERROR) << "Failed to open directory " << directory;
        return false;
    }
    if (ioctl(fd, FS_IOC_SET_ENCRYPTION_POLICY, get_policy(fep))) {
        PLOG(ERROR) << "Failed to set encryption policy for " << directory;
        close(fd);
        return false;
    }
    close(fd);
    return true;
}

extern "C" bool fscrypt_policy_get_struct(const char *directory, fscrypt_policy *fep) {
    int fd = open(directory, O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open directory " << directory;
        return false;
    }
    memset(fep, 0, sizeof(fscrypt_policy));
    struct fscrypt_get_policy_ex_arg ex_policy = {0};

    if (android::vold::isFsKeyringSupported()) {
        ex_policy.policy_size = sizeof(ex_policy.policy);
        if (ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY_EX, &ex_policy) != 0) {
            PLOG(ERROR) << "Failed to get encryption policy for " << directory;
            close(fd);
            return false;
        }
    } else {
        if (ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY, &ex_policy.policy.v1) != 0) {
            PLOG(ERROR) << "Failed to get encryption policy for " << directory;
            close(fd);
            return false;
        }
    }
    memcpy(fep, &ex_policy.policy, sizeof(ex_policy.policy));
    close(fd);
    return true;
}

extern "C" uint8_t* get_policy_descriptor(fscrypt_policy* fep) {
	if (!fep) return NULL;
	switch(fep->version) {
		case FSCRYPT_POLICY_V1:
			return fep->v1.master_key_descriptor;
		case FSCRYPT_POLICY_V2:
			return fep->v2.master_key_identifier;
		default:
			return NULL;
	}
}

extern "C" uint8_t get_policy_size(fscrypt_policy* fep, bool hex) {
	if (!fep) return 0;
	switch(fep->version) {
		case FSCRYPT_POLICY_V1:
			return hex ? FS_KEY_DESCRIPTOR_SIZE_HEX : FSCRYPT_KEY_DESCRIPTOR_SIZE;
		case FSCRYPT_POLICY_V2:
			return hex ? FSCRYPT_KEY_IDENTIFIER_SIZE_HEX : FSCRYPT_KEY_IDENTIFIER_SIZE;
	}
	return 0;
}

extern "C" void* get_policy(const fscrypt_policy *fep) {
	if (!fep) return NULL;
	switch(fep->version) {
		case FSCRYPT_POLICY_V1:
			return (void*)&(fep->v1);
		case FSCRYPT_POLICY_V2:
			return (void*)&(fep->v2);
	}
	return NULL;
}

extern "C" int fscrypt_policy_size(const fscrypt_policy *fep) {
	switch (fep->version) {
		case FSCRYPT_POLICY_V1:
			return sizeof(fep->v1);
		case FSCRYPT_POLICY_V2:
			return sizeof(fep->v2);
	}
	return 0;
}

extern "C" int fscrypt_policy_size_from_version(uint8_t version) {
	switch (version) {
		case FSCRYPT_POLICY_V1:
			return sizeof(fscrypt_policy_v1);
		case FSCRYPT_POLICY_V2:
			return sizeof(fscrypt_policy_v2);
	}
	return 0;
}

void get_policy_content(fscrypt_policy* fep, char* content) {
	if (!fep || !content) return;
	switch(fep->version) {
		case FSCRYPT_POLICY_V1:
			sprintf(content, "%i %i %i %i %s", (int)fep->v1.version,
				(int)fep->v1.contents_encryption_mode,
				(int)fep->v1.filenames_encryption_mode,
				(int)fep->v1.flags,
				fep->v1.master_key_descriptor);
			break;
		case FSCRYPT_POLICY_V2:
			sprintf(content, "%i %i %i %i %s", (int)fep->v2.version,
				(int)fep->v2.contents_encryption_mode,
				(int)fep->v2.filenames_encryption_mode,
				(int)fep->v2.flags,
				fep->v2.master_key_identifier);
			break;
	}
}
