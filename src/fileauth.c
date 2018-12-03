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


/* fileauth.c - a EPKA (External Public Key Authentication) Plug-in
 * for Dropbear that performs a similar operation as dropbear that reads
 * the list of public keys from ~/.ssh/authorized_keys file
 *
 * You must specify the file containing the keys in the plugin
 * options (see option -A of dropbear).
 *
 * The format of the file is a JSON array of objects with the following properties:
 *  "user": string     - Name of the user for which the key apply
 *  "keytype": string  - A valid key type supported (i.e. "ssh-rsa", "ssh-dsa", ...)
 *  "key": string      - Base-64 encoded public key
 *  "options": string  - [optional] session options
 *  "comments": string - [optional] Comments associated with this entry
 *
 *
 * Requires the cJSON library cJSON from: https://github.com/DaveGamble/cJSON
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "common.h"
#include "pubkeyapi.h"      /* The EPKA API */

#define PLUGIN_NAME             "fileauth"

#define MSG_PREFIX              "[" PLUGIN_NAME "] - "

/*
 * The following function is implemented in dropbear (it's part of
 * the libtomcrypt, included in dropbear). For the plugin to be 
 * able to access global symbols defined in the loader application
 * (dropbear) you need to link dropbear with the option -rdynamic
 *
 *
   Relaxed base64 decode a block of memory
   @param in       The base64 data to decode
   @param inlen    The length of the base64 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @return CRYPT_OK(0) if successful
*/
extern int base64_decode(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen);

/* The plugin instance, extends EPKAInstance */
struct MyPlugin {
    struct EPKAInstance     m_parent;

    int                     m_verbose;
    char *                  m_fileName;     /* strdup'd */
    cJSON *                 m_jsonRoot;     /* must free with cJSON_Delete */
};

/* The ssh session: extends EPKASession */
struct MySession {
    struct EPKASession      m_parent;
    
    /* Cached User: set during pre-auth, it's reused during the 2nd call to
     * avoid re-scanning the entire file
     */
    cJSON *                 m_cachedUser;
    const char *            m_cachedUserName;   /* Ptr to the cachedUser json object */
};

/* Returns 1 if success (key match), 0 if key don't match */
static int compareKey(const char *keyblob, unsigned int keybloblen, const char *encodedKey) {
    char *buf = NULL;
    unsigned long bufLen = strlen(encodedKey) * 2;
    int retVal = 0;

    buf = malloc(bufLen);

    if (base64_decode(encodedKey, strlen(encodedKey), &buf[0], &bufLen) != 0) {
        /* Decode failure */
        printf(MSG_PREFIX "base64 decode fail\n");
        goto done;
    }
    /* Decode success, compare binary values */
    if (keybloblen != bufLen) {
        /* Key size mismatch */
        printf(MSG_PREFIX "Key size mismatch: in=%u, decodedKey=%lu\n", keybloblen, bufLen);
        goto done;
    }
    retVal = memcmp(keyblob, buf, keybloblen) == 0;

done:
    if (buf) {
        free(buf);
    }
    return retVal;
}

/* Returns 1 if success, 0 if auth failed */
static int matchLine(cJSON *node,
        const char* algo, 
        unsigned int algolen,
        const unsigned char* keyblob, 
        unsigned int keybloblen,
        const char *username) {
    cJSON *jsonUser;
    cJSON *jsonKeytype;
    cJSON *jsonKey;

    jsonUser = cJSON_GetObjectItem(node, "user");
    if (!jsonUser || jsonUser->type != cJSON_String) {
        /* Missing 'user' or invalid type */
        return 0;
    }
    jsonKeytype = cJSON_GetObjectItem(node, "keytype");
    if (!jsonKeytype || jsonKeytype->type != cJSON_String) {
        /* Missing 'keytype' or invalid type */
        return 0;
    }
    jsonKey = cJSON_GetObjectItem(node, "key");
    if (!jsonKey || jsonKey->type != cJSON_String) {
        /* Missing 'key' or invalid type */
        return 0;
    }
    
    if (strcmp(username, jsonUser->valuestring)) {
        /* User mismatch */
        return 0;
    }
    if (strncmp(algo, jsonKeytype->valuestring, algolen)) {
        /* Algo mismatch */
        return 0;
    }
    if (!compareKey(keyblob, keybloblen, jsonKey->valuestring)) {
        /* Key mismatch */
        return 0;
    }
    /* Match */
    return 1;
}

static int MyCheckPubKey(struct EPKAInstance *instance, 
        struct EPKASession **sessionInOut,
        const char* algo, 
        unsigned int algolen,
        const unsigned char* keyblob, 
        unsigned int keybloblen,
        const char *username) {
    struct MyPlugin * me = (struct MyPlugin *)instance;
    struct MySession *retVal = (struct MySession *)*sessionInOut;

    if (me->m_verbose) {
        printf(MSG_PREFIX "checking user '%s'...\n", username);
    }
    if (!retVal) {
        /* Authenticate by scanning the JSON file */
        cJSON *node;
        cJSON *optionNode;
        cJSON *foundNode = NULL;
        for (node = me->m_jsonRoot->child; node; node = node->next) {
            if (matchLine(node, algo, algolen, keyblob, keybloblen, username)) {
                /* Yes, I know you can interrupt the search now, but by always 
                 * scanning the entire list of users, you can prevent discovery of
                 * all the user names in the JSON file by measuring the failure time.
                 * If you always scan the file, your failure time will remain constant.
                 */
                foundNode = node;
            }
        }
        if (!foundNode) {
            /* Auth failed: no match */
            if (me->m_verbose) {
                printf(MSG_PREFIX "pre-auth failed: no matching entry\n");
            }
            return -1;
        }

        /* Auth success */

        /* Create a new session */
        retVal = calloc(1, sizeof(*retVal));
        if (!retVal) {
            return -1; /* Failure */
        }

        retVal->m_parent.plugin_instance = instance;

        retVal->m_cachedUser = foundNode;    /* Save ptr to auth entry */
        retVal->m_cachedUserName = cJSON_GetObjectItem(foundNode, "user")->valuestring;  /* Already guaranteed it exist */
        optionNode = cJSON_GetObjectItem(foundNode, "options");
        if (optionNode && optionNode->type == cJSON_String) {
            retVal->m_parent.auth_options = optionNode->valuestring;
            retVal->m_parent.auth_options_length = strlen(retVal->m_parent.auth_options);
        }
        *sessionInOut = &retVal->m_parent;
        if (me->m_verbose) {
            printf(MSG_PREFIX "user '%s' pre-auth success\n", username);
        }

    } else {

        /* Already pre-auth, just validate the current node */
        if (!matchLine(retVal->m_cachedUser, algo, algolen, keyblob, keybloblen, username)) {
            /* Failed */
            if (me->m_verbose) {
                printf(MSG_PREFIX "pre-auth failed: no matching entry\n");
                return -1; /* Failure */
            }
        }
        if (me->m_verbose) {
            printf(MSG_PREFIX "user '%s' auth validated\n", username);
        }
    }
    return 0;   /* Success */
}

static void MyAuthSuccess(struct EPKASession *_session) {
    struct MySession *session = (struct MySession *)_session;
    struct MyPlugin *me = (struct MyPlugin *)_session->plugin_instance;

    if (me->m_verbose) {
        printf(MSG_PREFIX "auth_success called - user = %s\n", session->m_cachedUserName);
    }
}

static void MyDeleteSession(struct EPKASession *_session) {
    struct MySession *session = (struct MySession *)_session;
    struct MyPlugin *me = (struct MyPlugin *)_session->plugin_instance;

    if (session) {
        if (_session->auth_options) {
            free(_session->auth_options);
            _session->auth_options = NULL;
            _session->auth_options_length = 0;
        }
        free(session);
        if (me->m_verbose) {
            printf(MSG_PREFIX "session_deleted\n");
        }
    }
}

static void MyDeletePlugin(struct EPKAInstance *instance) {
    struct MyPlugin * me = (struct MyPlugin *)instance;

    if (me) {
        int verbose = me->m_verbose;
        if (me->m_fileName) {
            free(me->m_fileName);
        }
        if (me->m_jsonRoot) {
            cJSON_Delete(me->m_jsonRoot);
        }
        memset(me, 0, sizeof(*me));
        free(me);
        if (verbose) {
            printf(MSG_PREFIX "plugin deleted\n");
        }
    }

}

/* The plugin entry point */
void * plugin_new(int verbose, const char *options, const char *addrstring) {
    struct MyPlugin *retVal;
    FILE *fp;
    cJSON *jsonRoot;
    char *confFile = NULL;
    long confFileLength = 0;
    const char *errMsg = NULL;

    if (!options) {
        printf(MSG_PREFIX "missing auth file from options\n");
        goto err;
    }
    if (!readFile(options,  &confFile, &confFileLength, &errMsg)) {
        printf(MSG_PREFIX "error reading configuration file '%s': %s\n", options, errMsg);
        goto err;
    }

    jsonRoot = cJSON_Parse(confFile);
    if (!jsonRoot) {
        printf(MSG_PREFIX "error parsing configuration file '%s'\n", options);
        goto err;
    }

    /* Perform a simple validation of the JSON file and verify that the root object is
     * an array */
    if (jsonRoot->type != cJSON_Array) {
        printf(MSG_PREFIX "error in configuration file: expected root array\n");
        goto err;
    }


    retVal = calloc(1, sizeof(*retVal));
    retVal->m_parent.api_version[0] = DROPBEAR_EPKA_VERSION_MAJOR;
    retVal->m_parent.api_version[1] = DROPBEAR_EPKA_VERSION_MINOR;

    retVal->m_parent.checkpubkey = MyCheckPubKey;
    retVal->m_parent.auth_success = MyAuthSuccess;
    retVal->m_parent.delete_session = MyDeleteSession;
    retVal->m_parent.delete_plugin = MyDeletePlugin;
    retVal->m_verbose = verbose;
    retVal->m_fileName = strdup(options);
    retVal->m_jsonRoot = jsonRoot;

    if (verbose) {
        printf(MSG_PREFIX "plugin initialized - config file = %s, clientIP=%s\n", (options ? options : "<N/A>"), addrstring);
    }
    return &retVal->m_parent;

err:
    if (jsonRoot) {
        cJSON_Delete(jsonRoot);
    }
    if (confFile) {
        free(confFile);
    }
    return NULL;
}



