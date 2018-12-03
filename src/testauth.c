/*
 * dropbear_epka - EPKA Auth Plugin for Dropbear
 * 
 * Copyright (c) 2018 Fabrizio Bertocci
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pubkeyapi.h"      /* The EPKA API */

#define PLUGIN_NAME             "testauth"

#define MSG_PREFIX              "[" PLUGIN_NAME "] - "

/* The plugin instance, extends EPKAInstance */
struct MyPlugin {
    struct EPKAInstance     m_parent;

    int                     m_verbose;
};

/* The ssh session: extends EPKASession */
struct MySession {
    struct EPKASession      m_parent;

    int                     m_clientId;
};


static int MyCheckPubKey(struct EPKAInstance *instance, 
        struct EPKASession **sessionInOut,
        const char* algo, 
        unsigned int algolen,
        const unsigned char* keyblob, 
        unsigned int keybloblen,
        const char *username) {
    struct MyPlugin * me = (struct MyPlugin *)instance;
    struct MySession *retVal = (struct MySession *)*sessionInOut;
    printf(MSG_PREFIX "checkpubkey called - User=%s\n", username);
    if (!retVal) {
        retVal = calloc(1, sizeof(*retVal));
        if (!retVal) {
            return -1; /* Failure */
        }
        retVal->m_parent.plugin_instance = instance;

        retVal->m_clientId = random();
        retVal->m_parent.auth_options = strdup("no-X11-forwarding,no-pty");
        retVal->m_parent.auth_options_length = strlen(retVal->m_parent.auth_options);
        *sessionInOut = &retVal->m_parent;
    } 

    return 0;   /* Success */
}

static void MyAuthSuccess(struct EPKASession *_session) {
    struct MySession *session = (struct MySession *)_session;
    struct MyPlugin *me = (struct MyPlugin *)_session->plugin_instance;

    printf(MSG_PREFIX "auth_success called - clientID = %d\n", session->m_clientId);
}

static void MyDeleteSession(struct EPKASession *_session) {
    struct MySession *session = (struct MySession *)_session;
    struct MyPlugin *me = (struct MyPlugin *)_session->plugin_instance;

    printf(MSG_PREFIX "session_deleted\n");
    if (_session->auth_options) {
        free(_session->auth_options);
        _session->auth_options = NULL;
        _session->auth_options_length = 0;
    }
    free(session);
}

static void MyDeletePlugin(struct EPKAInstance *instance) {
    struct MyPlugin * me = (struct MyPlugin *)instance;

    free(me);
    
    printf(MSG_PREFIX "plugin_delete called\n");
}

void * plugin_new(int verbose, const char *options, const char *addrstring) {
    struct MyPlugin *retVal;
    if (!options) options = "<NULL>";
    printf(MSG_PREFIX "plugin_init called - options = %s, clientIP=%s\n", options, addrstring);
    retVal = calloc(1, sizeof(*retVal));
    retVal->m_parent.api_version[0] = DROPBEAR_EPKA_VERSION_MAJOR;
    retVal->m_parent.api_version[1] = DROPBEAR_EPKA_VERSION_MINOR;

    retVal->m_parent.checkpubkey = MyCheckPubKey;
    retVal->m_parent.auth_success = MyAuthSuccess;
    retVal->m_parent.delete_session = MyDeleteSession;
    retVal->m_parent.delete_plugin = MyDeletePlugin;
    retVal->m_verbose = verbose;

    return &retVal->m_parent;
}


