#
# Copyright (c) 2025 Contributors to the Eclipse Foundation.
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License, Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
#
# Standard imports
import sys
from functools import cache
from typing import Tuple
from hashlib import sha256
from base64 import b64encode, b32encode

# Third party imports
# This is temporary fix, due to probably missing typing, which is reported
# to the upstream https://github.com/tpm2-software/tpm2-pytss/issues/362
# TODO correct after fix release will be implemented
from tpm2_pytss.ESAPI import ESAPI  # type: ignore
from tpm2_pytss.utils import NVReadEK, create_ek_template  # type: ignore
from tpm2_pytss.types import (  # type: ignore
    TPM2_HANDLE,
    TPM2B_PUBLIC,
    TPM2B_SENSITIVE_CREATE,
    TPMT_PUBLIC,
    TPM2_ALG,
    TPMA_OBJECT,
    TPMU_PUBLIC_PARMS,
    TPMS_RSA_PARMS,
    TPMS_ECC_PARMS,
    TPMT_SYM_DEF_OBJECT,
    TPMU_SYM_KEY_BITS,
    TPMU_SYM_MODE,
    TPMT_RSA_SCHEME,
    TPMT_ECC_SCHEME,
    TPMT_KDF_SCHEME
)
from tpm2_pytss.constants import TPM2_ECC, ESYS_TR  # type: ignore
from tpm2_pytss.TSS2_Exception import TSS2_Exception  # type: ignore

# Local imports
from mpa.common.logger import Logger
from mpa.device.common import TPM_PRESENCE_FILE

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


def is_tpm_present() -> bool:
    # only 'true' or 'false'
    is_present = TPM_PRESENCE_FILE.read_text().rstrip()
    if is_present == "true":
        return True
    elif is_present == "false":
        return False
    raise RuntimeError(f"Unrecognized option '{is_present}' for TPM presence defined in {TPM_PRESENCE_FILE}")


@cache
def get_data_from_tpm_module() -> Tuple[str, str]:
    """ Returns tuple of two strings: (registration_id, endorsement_key) """
    if not is_tpm_present():
        return "N/A", "N/A"
    # Addresses are taken from TPM documentation (and verified to be same as in
    # https://github.com/Azure/azure-iot-sdk-c/blob/main/provisioning_client/src/sec_device_module_tpm.c#L22)
    TPM2_EK_HANDLE = 0x81010001
    TPM2_SRK_HANDLE = 0x81000001

    def get_public(handle: TPM2_HANDLE) -> TPM2B_PUBLIC:
        with ESAPI() as ectx:
            try:
                object_handle = ectx.tr_from_tpmpublic(handle)
                pub, _, _ = ectx.read_public(object_handle)
                ectx.tr_close(object_handle)
                return pub
            except TSS2_Exception:
                return None

    def create_ek_pub() -> TPM2B_PUBLIC:
        """ Reading TPM endorsement key is described on https://github.com/tpm2-software/tpm2-pytss/issues/350 """
        with ESAPI() as ectx:
            nv_read = NVReadEK(ectx)
            # EK-ECC256 for elliptic curve
            _, templ = create_ek_template("EK-RSA2048", nv_read)
            object_handle, pub, _, _, _ = ectx.create_primary(TPM2B_SENSITIVE_CREATE(), templ, ESYS_TR.ENDORSEMENT)
            ectx.evict_control(ESYS_TR.OWNER, object_handle, TPM2_EK_HANDLE)
            ectx.tr_close(object_handle)
            return pub

    def create_srk_pub(type: str = 'rsa') -> None:
        def get_srk_template(type: str) -> TPMT_PUBLIC:
            srk_attributes = (TPMA_OBJECT.USERWITHAUTH
                              | TPMA_OBJECT.RESTRICTED
                              | TPMA_OBJECT.DECRYPT
                              | TPMA_OBJECT.NODA
                              | TPMA_OBJECT.FIXEDTPM
                              | TPMA_OBJECT.FIXEDPARENT
                              | TPMA_OBJECT.SENSITIVEDATAORIGIN)

            match type:
                case 'rsa':
                    srk_template = TPMT_PUBLIC(
                        type=TPM2_ALG.RSA,
                        nameAlg=TPM2_ALG.SHA256,
                        objectAttributes=srk_attributes,
                        parameters=TPMU_PUBLIC_PARMS(
                            rsaDetail=TPMS_RSA_PARMS(
                                symmetric=TPMT_SYM_DEF_OBJECT(
                                    algorithm=TPM2_ALG.AES,
                                    keyBits=TPMU_SYM_KEY_BITS(aes=128),
                                    mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
                                ),
                                scheme=TPMT_RSA_SCHEME(scheme=TPM2_ALG.NULL),
                                keyBits=2048,
                                exponent=0,
                            ),
                        ),
                    )
                case 'ecc':
                    srk_template = TPMT_PUBLIC(
                        type=TPM2_ALG.ECC,
                        nameAlg=TPM2_ALG.SHA256,
                        objectAttributes=srk_attributes,
                        parameters=TPMU_PUBLIC_PARMS(
                            eccDetail=TPMS_ECC_PARMS(
                                symmetric=TPMT_SYM_DEF_OBJECT(
                                    algorithm=TPM2_ALG.AES,
                                    keyBits=TPMU_SYM_KEY_BITS(aes=128),
                                    mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
                                ),
                                scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                                curveID=TPM2_ECC.NIST_P256,
                                kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
                            ),
                        ),
                    )
                case _:
                    raise RuntimeError(f"Unknown srk key type: {type}, expected ecc or rsa")

            return srk_template

        srk_template = TPM2B_PUBLIC(publicArea=get_srk_template(type))
        with ESAPI() as ectx:
            object_handle, _, _, _, _ = ectx.create_primary(TPM2B_SENSITIVE_CREATE(), srk_template, ESYS_TR.OWNER)
            ectx.evict_control(ESYS_TR.OWNER, object_handle, TPM2_SRK_HANDLE)
            ectx.tr_close(object_handle)

    if (ek_pub := get_public(TPM2_EK_HANDLE)) is None:
        ek_pub = create_ek_pub()

    if get_public(TPM2_SRK_HANDLE) is None:
        create_srk_pub()

    hash_function = sha256()
    hash_function.update(ek_pub.marshal())
    reg_id = b32encode(hash_function.digest()).replace(b'=', b'').decode().lower()
    end_key = b64encode(ek_pub.marshal()).decode()

    return reg_id, end_key
