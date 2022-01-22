/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "coauth_sign_centre.h"

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_time.h"

#define TOKEN_VALIDITY_PERIOD (10 * 60 * 1000)

// Key used for coauth signature.
static uint8_t g_coAuthTokenKey[SHA256_KEY_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
};

static bool IsTimeValid(const ScheduleTokenHal *coAuthToken)
{
    uint64_t currentTime = GetSystemTime();
    if (currentTime < coAuthToken->time) {
        return false;
    }
    if (currentTime - coAuthToken->time > TOKEN_VALIDITY_PERIOD) {
        return false;
    }
    return true;
}

ResultCode CoAuthTokenSign(ScheduleTokenHal *coAuthToken)
{
    if (coAuthToken == NULL) {
        LOG_ERROR("coAuthToken is NULL");
        return RESULT_BAD_PARAM;
    }
    coAuthToken->version = TOKEN_VERSION;
    ResultCode ret = RESULT_SUCCESS;
    Buffer *data = CreateBufferByData((uint8_t *)coAuthToken, COAUTH_TOKEN_DATA_LEN);
    Buffer *key = CreateBufferByData(g_coAuthTokenKey, SHA256_KEY_LEN);
    Buffer *sign = NULL;
    if (data == NULL || key == NULL) {
        LOG_ERROR("lack of member");
        ret = RESULT_NO_MEMORY;
        goto EXIT;
    }

    if (HmacSha256(key, data, &sign) != RESULT_SUCCESS || !IsBufferValid(sign)) {
        ret = RESULT_GENERAL_ERROR;
        goto EXIT;
    }

    if (memcpy_s(coAuthToken->sign, SHA256_SIGN_LEN, sign->buf, sign->contentSize) != EOK) {
        LOG_ERROR("sign copy failed");
        ret = RESULT_BAD_COPY;
        goto EXIT;
    }

EXIT:
    DestoryBuffer(data);
    DestoryBuffer(key);
    DestoryBuffer(sign);
    return ret;
}

ResultCode CoAuthTokenVerify(const ScheduleTokenHal *coAuthToken)
{
    if (coAuthToken == NULL) {
        LOG_ERROR("coAuthToken is NULL");
        return RESULT_BAD_PARAM;
    }

    if (!IsTimeValid(coAuthToken)) {
        LOG_ERROR("token timeout");
        return RESULT_TOKEN_TIMEOUT;
    }
    ResultCode ret = RESULT_SUCCESS;
    Buffer *data = CreateBufferByData((uint8_t *)coAuthToken, COAUTH_TOKEN_DATA_LEN);
    Buffer *key = CreateBufferByData(g_coAuthTokenKey, SHA256_KEY_LEN);
    Buffer *sign = CreateBufferByData(coAuthToken->sign, SHA256_SIGN_LEN);
    Buffer *rightSign = NULL;
    if (data == NULL || key == NULL || sign == NULL) {
        LOG_ERROR("lack of member");
        ret = RESULT_NO_MEMORY;
        goto EXIT;
    }

    if (HmacSha256(key, data, &rightSign) != RESULT_SUCCESS || !IsBufferValid(rightSign)) {
        ret = RESULT_GENERAL_ERROR;
        goto EXIT;
    }

    if (!CompareBuffer(rightSign, sign)) {
        LOG_ERROR("sign compare failed ");
        ret = RESULT_BAD_SIGN;
    }

EXIT:
    DestoryBuffer(data);
    DestoryBuffer(key);
    DestoryBuffer(sign);
    DestoryBuffer(rightSign);
    return ret;
}