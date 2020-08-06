/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "arch.h"
#include "sgx_error.h"
#include "tcs.h"
#include "se_trace.h"
#include "rts.h"
#include "enclave.h"
#include "sig_handler.h"
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <errno.h>


typedef struct _ecall_param_t
{
    tcs_t *tcs;
    long   fn;              //long because we need register bandwith align on stack, refer to enter_enclave.h;
    void *ocall_table;
    void *ms;
    CTrustThread *trust_thread;
} ecall_param_t;

#ifdef __x86_64__
#define REG_XIP REG_RIP
#define REG_XAX REG_RAX
#define REG_XBX REG_RBX
#define REG_XSI REG_RSI
#define REG_XBP REG_RBP
/*
 * refer to enter_enclave.h
 * stack high address <-------------
 * |rip|rbp|rbx|r10|r13|r14|r15|r8|rcx|rdx|rsi|rdi|
 *         ^                     ^
 *         | <-rbp               | <-param4
 */
#define ECALL_PARAM (reinterpret_cast<ecall_param_t*>(context->uc_mcontext.gregs[REG_RBP] - 10 * 8))
#else
#define REG_XIP REG_EIP
#define REG_XAX REG_EAX
#define REG_XBX REG_EBX
#define REG_XSI REG_ESI
#define REG_XBP REG_EBP
/*
 * refer to enter_enclave.h
 * stack high address <-------------
 * |param4|param3|param2|param2|param0|eip|ebp|
 *                                            ^
 *                                            | <-ebp
 */
#define ECALL_PARAM (reinterpret_cast<ecall_param_t*>(context->uc_mcontext.gregs[REG_EBP] + 2 * 4))
#endif

extern "C" void *get_aep();
extern "C" void *get_eenterp();
extern "C" void *get_eretp();

//trust_thread is saved at stack for ocall.
#define enter_enclave __morestack

extern "C" int enter_enclave(const tcs_t *tcs, const long fn, const void *ocall_table, const void *ms, CTrustThread *trust_thread);


int do_ecall(const int fn, const void *ocall_table, const void *ms, CTrustThread *trust_thread)
{
    int status = SGX_ERROR_UNEXPECTED;

#ifdef SE_SIM
    CEnclave* enclave = trust_thread->get_enclave();
    //check if it is current pid, it is to simulate fork() scenario on HW
    sgx_enclave_id_t eid = enclave->get_enclave_id();
    if((pid_t)(eid >> 32) != getpid())
        return SGX_ERROR_ENCLAVE_LOST;
#endif

    tcs_t *tcs = trust_thread->get_tcs();

    status = enter_enclave(tcs, fn, ocall_table, ms, trust_thread);

    return status;
}

int do_ocall(const bridge_fn_t bridge, void *ms)
{
    int error = SGX_ERROR_UNEXPECTED;

    error = bridge(ms);

    return error;
}