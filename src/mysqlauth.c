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


/* mysqlauth.c - a EPKA (External Public Key Authentication) Plug-in
 * for Dropbear that reads user and public key from a MySQL database
 *
 * The configuration of MySQL is in a configuration file that need to be
 * specified through the plugin option (see -A option of dropbear).
 *
 * The plugin configuration file is a JSON file containing the following properties:
 * "dbHost": string      - The host or IP address of the MySQL server
 * "dbPort": number      - The port where the MySQL server is listening for connections
 * "dbUser": string      - The user name for the MySQL connection
 * "dbPass": string      - The password to use when connecting to MySQL
 * "dbName": string      - The name of the database to use
 * "tableAuth": string   - The name of the table containing auth information'
 * "tableStatus": string - [OPTIONAL] Name of the table where to update the connectivity status for the client
 * "tableLog": string    - [OPTIONAL] Name of the table where to log the event
 *
 * Configurable Column Information - All those values are OPTIONAL strings. Default values are provided:
 * "colClientId": ["client_id"] Name of the column that identify the client connecting to the server
 * "colAuthUser": ["user"] Name of the user
 * "colAuthKeyform": ["keyform"] Key form as string
 * "colAuthPubkey": ["pubkey"] Key in binary format
 * "colAuthKeyhash": ["keyhash"] Keyhash in  binary format (SHA256)
 * "colAuthOptions": ["options"] Options as string
 * "colStatusConnected": ["connected"] Connected status flag as integer
 * "colStatusPid": ["pid"] PID of dropbear server child
 * "colStatusAddress": ["address"] IP address of client
 * "colLogTs": ["ts"] DATETIME of the event
 * "colLogEvent": ["event"] String of the event ('CONNECTED' or 'DISCONNECTED')
 *
 * The plugin will read from table:
 * $dbName.$tableAuth the following columns:
 *  - $colClientId (string)   - Used to correlate the status table - CAN BE NULL
 *  - $colAuthUser (string)
 *  - $colAuthKeyform (string)
 *  - $colAuthPubkey (in binary form)
 *  - $colAuthKeyhash (SHA256 of the public key in binary form)
 *  - $colAuthOptions - CAN BE NULL
 *
 * The plugin will modify the following tables:
 * $dbName.$tableStatus - UPDATE
 *  - $colClientId (string) from the auth table
 *  - $colCStatusConnected: Number  0=disconnected, 1=connected
 *
 * $dbName.$tableLog - INSERT
 *  - $colClientId (string)
 *  - $colLogTs (DATETIME)
 *  - $colLogEvent (string) will write 'CONNECTED' or 'DISCONNECTED'
 *
 *
 * Requires the cJSON library cJSON from: https://github.com/DaveGamble/cJSON
 * Requires libmysqlclient-dev
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

#include <my_global.h>
#include <mysql.h>

#include <sys/types.h>      /* For getpid() */
#include <unistd.h>

#include "common.h"
#include "pubkeyapi.h"      /* The EPKA API */


/* Dropbear logger */
#include <syslog.h>         // For LOG_WARNING, LOG_INFO, ...
extern void dropbear_log(int priority, const char* format, ...);
#define DROPBEAR_SUCCESS 0
#define DROPBEAR_FAILURE -1

#define PLUGIN_NAME             "mysqlauth"

#define MSG_PREFIX              "[" PLUGIN_NAME "] - "

/* The plugin instance, extends EPKAInstance */
struct MyPlugin {
    struct EPKAInstance     m_parent;
 
    MYSQL *                 m_dbConn;
    MYSQL_STMT *            m_authStmt;

    int                     m_verbose;
    char *                  m_clientIp;     // strdup of IP address, optional - Only IP, not the port

    /* Configuration from the JSON File */
    cJSON *                 m_configRoot;

    /* The following char * points to the memory allocated by the cJSON parser
     * and will be freed when the JSON object is destroyed
     */
    char *                  m_tableAuth;
    char *                  m_tableStatus;  // Can be NULL
    char *                  m_tableLog;     // Can be NULL

    // Table Auth columns
    char *                  m_colClientId;
    char *                  m_colAuthUser;
    char *                  m_colAuthKeyform;
    char *                  m_colAuthPubkey;
    char *                  m_colAuthKeyhash;
    char *                  m_colAuthOptions;

    // Table Status column
    char *                  m_colStatusConnected;
    char *                  m_colStatusPid;
    char *                  m_colStatusAddress;

    // Table Log column
    char *                  m_colLogTs;
    char *                  m_colLogEvent;
};

// The Precompiled statement:
static const char * const PRECOMP_STATEMENT_STRING = 
//               cli   opts  pubkey    table      user       keyform    keyhash
//               |     |     |         |          |          |          |
        "SELECT `%s`, `%s`, `%s` FROM `%s` WHERE `%s`=? AND `%s`=? AND `%s`=UNHEX(SHA2(?, 256))";
//               |     |     |                        |          |                     |
//               r0    r1    r2                       q0         q1                    q2

static const char * const AUTH_SUCCESS_QUERY = 
//               table    conn  1/0  pid   xxx  addr   IP          cliId   val
//               |        |     |    |     |    |      |           |       |
        "UPDATE `%s` SET `%s` = %d, `%s` = %d, `%s` = \"%s\" WHERE `%s` = \"%s\"";

static const char * const LOG_ENTRY_QUERY = 
//                    table cli   ts    event          cli            event
//                    |     |     |     |              |              |
        "INSERT INTO `%s` (`%s`, `%s`, `%s`) VALUES (\"%s\", now(), \"%s\")";

static const char * const LOG_ENTRY_KEYWORD_CONNECTED    = "CONNECT";
static const char * const LOG_ENTRY_KEYWORD_DISCONNECTED = "DISCONN";

/* The ssh session: extends EPKASession */
struct MySession {
    struct EPKASession      m_parent;
   
    // Cached data: read during pre-auth is reused when dropbear authenticate client 
    // All those buffers must be freed when the session is destroyed
    char *                  m_options;
    char *                  m_username;
    char *                  m_keyblob;
    unsigned int            m_keybloblen;
    char *                  m_clientId;
};


// {{{ readProperty
// ----------------------------------------------------------------------------
// Returns 1 if success, 0 if an error occurred
static int readProperty(cJSON *jsonRoot, 
        const char *propertyName, 
        int isMandatory,
        char *defaultValue,     // If defaultValue is NULL, param is mandatory
        char **valueOut) {
    cJSON *val = cJSON_GetObjectItem(jsonRoot, propertyName);
    if (!val) {
        if (isMandatory) {
            dropbear_log(LOG_ERR, MSG_PREFIX "Missing mandatory property from config file: %s", propertyName);
            return 0;
        }
        *valueOut = defaultValue;
    } else {
        *valueOut = val->valuestring;
    }
    return 1;
}

// }}}
// {{{ initFromConfig
// ----------------------------------------------------------------------------
// Returns 1 if success, 0 if an error occurred
static int initFromConfig(struct MyPlugin *me, const char *configFile) {
    const char *errMsg =  NULL;
    char *fileContent = NULL;
    long fileLength = 0;
    char *dbHost;
    int   dbPort = 3306;
    char *dbUser;
    char *dbPass;
    char *dbName;
    cJSON *val;
    int retVal = 0; /* Error */
    char *stmt = NULL;
    size_t stmtLen;

    if (!readFile(configFile, &fileContent, &fileLength, &errMsg)) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Error reading configuration file '%s': %s", configFile, errMsg);
        goto done;
    }

    me->m_configRoot = cJSON_Parse(fileContent);
    if (!me->m_configRoot) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Error parsing configuration file '%s'", configFile);
        goto done;
    }

    if ( !( 
            readProperty(me->m_configRoot, "dbHost", 1, NULL, &dbHost) &&
            readProperty(me->m_configRoot, "dbUser", 1, NULL, &dbUser) &&
            readProperty(me->m_configRoot, "dbPass", 1, NULL, &dbPass) &&
            readProperty(me->m_configRoot, "dbName", 1, NULL, &dbName) &&

            readProperty(me->m_configRoot, "tableAuth", 1, NULL, &me->m_tableAuth) &&
            readProperty(me->m_configRoot, "tableStatus", 0, NULL, &me->m_tableStatus) &&
            readProperty(me->m_configRoot, "tableLog", 0, NULL, &me->m_tableLog) &&

            readProperty(me->m_configRoot, "colClientId", 0, "client_id", &me->m_colClientId) &&
            readProperty(me->m_configRoot, "colAuthUser", 0, "user", &me->m_colAuthUser) &&
            readProperty(me->m_configRoot, "colAuthKeyform", 0, "keyform", &me->m_colAuthKeyform) &&
            readProperty(me->m_configRoot, "colAuthPubkey", 0, "pubkey", &me->m_colAuthPubkey) &&
            readProperty(me->m_configRoot, "colAuthKeyhash", 0, "keyhash", &me->m_colAuthKeyhash) &&
            readProperty(me->m_configRoot, "colAuthOptions", 0, "options", &me->m_colAuthOptions) &&

            readProperty(me->m_configRoot, "colStatusConnected", 0, "connected", &me->m_colStatusConnected) &&
            readProperty(me->m_configRoot, "colStatusPid", 0, "pid", &me->m_colStatusPid) &&
            readProperty(me->m_configRoot, "colStatusAddress", 0, "address", &me->m_colStatusAddress) &&

            readProperty(me->m_configRoot, "colLogTs", 0, "ts", &me->m_colLogTs) &&
            readProperty(me->m_configRoot, "colLogEvent", 0, "event", &me->m_colLogEvent) )) {
        goto done;
    }

    // Finally read the port (not a string)
    val = cJSON_GetObjectItem(me->m_configRoot, "dbPort");
    if (val) {
        dbPort = val->valueint;
    }

    // Connect to database
    me->m_dbConn = mysql_init(NULL);
    if (!me->m_dbConn) {
        goto done;
    }
    if (!mysql_real_connect(me->m_dbConn,
                dbHost,
                dbUser,
                dbPass,
                dbName,
                dbPort,
                NULL,                   // Unix socket
                0)) {                   // Client flags
        dropbear_log(LOG_ERR, MSG_PREFIX "Database connection failed: %s", mysql_error(me->m_dbConn));
        goto done;
    }

    /* Create precompiled statement */
    me->m_authStmt = mysql_stmt_init(me->m_dbConn);
    if (!me->m_authStmt) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Failed to initialize auth statement");
        goto done;
    }
    // Statement is something like this:
    //      SELECT * FROM <tableAuth> WHERE <user>=? AND <keyform>=? AND <keyhash>=SHA2(?, 256);
    stmtLen = strlen(PRECOMP_STATEMENT_STRING) + 
        strlen(me->m_colClientId) +
        strlen(me->m_colAuthOptions) +
        strlen(me->m_colAuthPubkey) +
        strlen(me->m_tableAuth) + 
        strlen(me->m_colAuthUser) + 
        strlen(me->m_colAuthKeyform) + 
        strlen(me->m_colAuthKeyhash) + 
        1;       // +1 for string terminator

    stmt = (char *)malloc(stmtLen);
    stmtLen = snprintf(stmt, stmtLen, PRECOMP_STATEMENT_STRING, 
            me->m_colClientId, 
            me->m_colAuthOptions,
            me->m_colAuthPubkey,
            me->m_tableAuth, 
            me->m_colAuthUser, 
            me->m_colAuthKeyform, 
            me->m_colAuthKeyhash);

    if (mysql_stmt_prepare(me->m_authStmt, stmt, stmtLen)) {
        dropbear_log(LOG_ERR, "Failed to prepare auth statement: %s", mysql_stmt_error(me->m_authStmt));
        goto done;
    }

    // Success!
    retVal = 1;
done:
    if (stmt) {
        free(stmt);
    }
    if (fileContent) {
        free(fileContent);
    }
    return retVal;
}
// }}}
// {{{ sqlRunQueryAuth
// ----------------------------------------------------------------------------
// Returns 1 if success, 0 if an error occurred
// If the query return no match, this function will return 1, but *pubkeyOut
// and *clientIdOut will be NULL.
// *optionsOut will be NULL also if the value is NULL (NULL is allowed for options)
// (also an empty value will return NULL on optionsOut)
static int sqlRunQueryAuth(struct MyPlugin *me,
        const char* algo, 
        unsigned int algolen,
        const unsigned char* keyblob, 
        unsigned int keybloblen,
        const char *username,
        char **clientIdOut,
        char **optionsOut,
        char **pubkeyOut,
        unsigned int *pubkeyOutLen) {

    int ok = 0;
    int rc;
    MYSQL_BIND queryBind[3];        // Query requires 3 arguments
    MYSQL_BIND resBind[3];          // Response contains 3 columns

    char *resClientId = NULL;
    my_bool resClientIdIsNull = 0;
    my_bool resClientIdIsError = 0;
    unsigned long resClientIdLen = 0;

    char *resOptions = NULL;
    my_bool resOptionsIsNull = 0;
    my_bool resOptionsIsError = 0;
    unsigned long resOptionsLen = 0;

    char *resPubkey = NULL;         // Dynamically allocated using prefetch
    my_bool resPubkeyIsNull = 0;
    my_bool resPubkeyIsError = 0;
    unsigned long resPubkeyLen;

    if (me->m_verbose) {
        dropbear_log(LOG_DEBUG, MSG_PREFIX "Pre-auth, user '%s'...", username);
    }

    *clientIdOut = NULL;
    *optionsOut = NULL;
    *pubkeyOut = NULL;
    *pubkeyOutLen = 0;
    memset(queryBind, 0, sizeof(queryBind));
    memset(resBind, 0, sizeof(resBind));

    // Query bind #0: user name
    queryBind[0].buffer_length = strlen(username);
    queryBind[0].buffer = strdup(username);
    queryBind[0].buffer_type = MYSQL_TYPE_STRING;

    // Query bind #1: keyform
    queryBind[1].buffer = malloc(algolen);
    if (!queryBind[1].buffer) {
        dropbear_log(LOG_CRIT, MSG_PREFIX "Out of memory duplicating algo");
        goto done;
    }
    queryBind[1].buffer_length = algolen;
    memcpy(queryBind[1].buffer, algo, algolen);
    queryBind[1].buffer_type = MYSQL_TYPE_STRING;

    // Query bind #2: the public key to authenticate
    queryBind[2].buffer = malloc(keybloblen);
    if (!queryBind[2].buffer) {
        dropbear_log(LOG_CRIT, MSG_PREFIX "Out of memory duplicating keyblob");
        goto done;
    }
    queryBind[2].buffer_length = keybloblen;
    memcpy(queryBind[2].buffer, keyblob, keybloblen);
    queryBind[2].buffer_type = MYSQL_TYPE_BLOB;

    if (mysql_stmt_bind_param(me->m_authStmt, &queryBind[0])) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Failed to bind params to SQL auth statement: %s", mysql_stmt_error(me->m_authStmt));
        goto done;
    }
    if (mysql_stmt_execute(me->m_authStmt)) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Failed to run auth statement: %s",mysql_stmt_error(me->m_authStmt));
        goto done;
    }

    // Response bind #0: clientID
    resBind[0].buffer_type = MYSQL_TYPE_STRING;
    resBind[0].buffer_length = 0;           // Pre-fetch
    resBind[0].buffer = NULL;
    resBind[0].is_null = &resClientIdIsNull;
    resBind[0].length = &resClientIdLen;
    resBind[0].error = &resClientIdIsError;

    // Response bind #1: Options
    resBind[1].buffer_type = MYSQL_TYPE_STRING;
    resBind[1].buffer_length = 0;           // Pre-fetch
    resBind[1].buffer = NULL;
    resBind[1].is_null = &resOptionsIsNull;
    resBind[1].length = &resOptionsLen;
    resBind[1].error = &resOptionsIsError;

    // Response bind #2: Options
    resBind[2].buffer_type = MYSQL_TYPE_BLOB;
    resBind[2].buffer_length = 0;           // Pre-fetch it to determine the real size of the public key
    resBind[2].buffer = NULL;               // No need to allocate anything during pre-fetch
    resBind[2].is_null = &resPubkeyIsNull;
    resBind[2].length = &resPubkeyLen;
    resBind[2].error = &resPubkeyIsError;

    if (mysql_stmt_bind_result(me->m_authStmt, &resBind[0])) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Failed to bind results to SQL auth statement: %s", mysql_stmt_error(me->m_authStmt));
        goto done;
    }

    // Prefetch row - Used only to determine the pubkey size
    if (mysql_stmt_fetch(me->m_authStmt) == MYSQL_NO_DATA) {
        // No match
        if (me->m_verbose) {
            dropbear_log(LOG_DEBUG, MSG_PREFIX "Non matching entries");
        }
        ok = 1;
        goto done;
    }

    // There is at least one row matching
    if (!resClientIdIsNull) {
        *clientIdOut = malloc(resClientIdLen);
        if (!*clientIdOut) {
            dropbear_log(LOG_CRIT, MSG_PREFIX "Out of memory allocating client ID (size=%d)", resClientIdLen);
            goto done;
        }
        resBind[0].buffer = *clientIdOut;
        resBind[0].buffer_length = resClientIdLen;
        rc = mysql_stmt_fetch_column(me->m_authStmt, &resBind[0], 0, 0);
        if (rc) {
            dropbear_log(LOG_ERR, MSG_PREFIX "Error getting clientId column: %s", mysql_stmt_error(me->m_authStmt));
            goto done;
        }
    } // else *clientIdOut is already NULL

    if (!resOptionsIsNull) {
        *optionsOut = malloc(resOptionsLen);
        if (!*optionsOut) {
            dropbear_log(LOG_CRIT, MSG_PREFIX "Out of memory allocating options (size=%d)", resOptionsLen);
            goto done;
        }
        resBind[1].buffer = *optionsOut;
        resBind[1].buffer_length = resOptionsLen;
        rc = mysql_stmt_fetch_column(me->m_authStmt, &resBind[1], 1, 0);
        if (rc) {
            dropbear_log(LOG_ERR, MSG_PREFIX "Error getting options column: %s", mysql_stmt_error(me->m_authStmt));
            goto done;
        }
    } // else *clientIdOut is already NULL

    // pubkey cannot be NULL
    if (resPubkeyIsNull) {
        dropbear_log(LOG_WARNING, MSG_PREFIX "Found NULL pubkey, invalid record");
        ok = 1;
        goto done;
    }
    *pubkeyOutLen =  resPubkeyLen;
    *pubkeyOut = malloc(resPubkeyLen);
    if (!*pubkeyOut) {
        dropbear_log(LOG_CRIT, MSG_PREFIX "Out of memory allocating pubkey (size=%d)", resPubkeyLen);
        goto done;
    }
    resBind[2].buffer = *pubkeyOut;
    resBind[2].buffer_length = resPubkeyLen;
    rc = mysql_stmt_fetch_column(me->m_authStmt, &resBind[2], 2, 0);
    if (rc) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Error getting pubkey column: %s", mysql_stmt_error(me->m_authStmt));
        goto done;
    }

    // Success
    ok = 1;

done:
    if (!ok) {
        if (*clientIdOut) free(*clientIdOut);
        if (*optionsOut) free(*optionsOut);
        if (*pubkeyOut) free(*pubkeyOut);
        *pubkeyOutLen = 0;
    }
    {
        int i;
        for (i = 0; i < 3; ++i) {
            if (queryBind[i].buffer) {
                free(queryBind[i].buffer);
            }
        }
    }
    mysql_stmt_reset(me->m_authStmt);
    return ok;
}

// }}}

// {{{ sqlRunStatusUpdate
// ----------------------------------------------------------------------------
// Returns 1 if the query was executed successfully, 0 if an error occurred or
// the query was skipped
int sqlRunStatusUpdate(struct MyPlugin *me, struct MySession *session, int statusInt, int pid) {
    char * query = NULL;
    size_t queryLen = 0;
    int ok = 0;
    queryLen = strlen(AUTH_SUCCESS_QUERY) + 
        strlen(me->m_tableStatus) +
        strlen(me->m_colStatusConnected) + 1 +      // 1 for the 1|0 value
        strlen(me->m_colStatusPid) + 7 +            // 7 chars for PID
        strlen(me->m_colStatusAddress) + 15 +       // 15 chars for addr
        strlen(me->m_colClientId) + strlen(session->m_clientId) +
        10;     // Add an extra 10 chars
    query = malloc(queryLen);
    if (!query) {
        dropbear_log(LOG_CRIT, MSG_PREFIX "Out of memory allocating status update query");
        return 0;
    }

    snprintf(query, queryLen, AUTH_SUCCESS_QUERY, 
            me->m_tableStatus,
            me->m_colStatusConnected, statusInt,
            me->m_colStatusPid, pid,
            me->m_colStatusAddress, (me->m_clientIp ? me->m_clientIp : ""),
            me->m_colClientId, session->m_clientId);

    /* Update records */
    if (mysql_query(me->m_dbConn, query)) {
        dropbear_log(LOG_WARNING, MSG_PREFIX "Database error updating status table. SQL='%s', err='%s'", 
                query, mysql_error(me->m_dbConn));
    } else {
        if (me->m_verbose) {
            dropbear_log(LOG_DEBUG, MSG_PREFIX "Successfully updated status table");
        }
        ok = 1;
    }
    free(query);
    return ok;
}

// }}}
// {{{ sqlRunLogInsert
// ----------------------------------------------------------------------------
// Returns 1 if the query was executed successfully, 0 if an error occurred or
// the query was skipped
int sqlRunLogInsert(struct MyPlugin *me, struct MySession *session, const char *evt) {
    char * query = NULL;
    size_t queryLen = 0;
    int ok = 0;
    queryLen = strlen(LOG_ENTRY_QUERY) + 
        strlen(me->m_tableLog) +
        strlen(me->m_colClientId) +
        strlen(me->m_colLogTs) +
        strlen(me->m_colLogEvent) +
        strlen(session->m_clientId) +
        20;     // event
    query = malloc(queryLen);
    if (!query) {
        dropbear_log(LOG_CRIT, MSG_PREFIX "Out of memory allocating log query");
        return 0;
    }

    snprintf(query, queryLen, LOG_ENTRY_QUERY, 
            me->m_tableLog,
            me->m_colClientId,
            me->m_colLogTs,
            me->m_colLogEvent,
            session->m_clientId, evt);

    /* Update records */
    if (mysql_query(me->m_dbConn, query)) {
        dropbear_log(LOG_WARNING, MSG_PREFIX "Database error updating log table. SQL='%s', err='%s'", 
                query, mysql_error(me->m_dbConn));
    } else {
        if (me->m_verbose) {
            dropbear_log(LOG_DEBUG, MSG_PREFIX "Successfully updated log table");
        }
        ok = 1;
    }
    free(query);
    return ok;
}

// }}}
// {{{ MyGetOptions
// ----------------------------------------------------------------------------
static char * MyGetOptions(struct EPKASession *_session) {
    struct MySession *session = (struct MySession *)_session;
    return session->m_options;
}

// }}}
// {{{ MyDeletePlugin
// ----------------------------------------------------------------------------
static void MyDeletePlugin(struct EPKAInstance *instance) {
    struct MyPlugin * me = (struct MyPlugin *)instance;

    if (me) {
        int verbose = me->m_verbose;
        if (me->m_authStmt) {
            mysql_stmt_close(me->m_authStmt);
            me->m_authStmt = NULL;
        }
        if (me->m_dbConn) {
            mysql_close(me->m_dbConn);
            me->m_dbConn = NULL;
        }
        if (me->m_configRoot) {
            cJSON_Delete(me->m_configRoot);
            me->m_configRoot = NULL;
            // As well as all the pointers to config parameters gets invalidated
        }
        memset(me, 0, sizeof(*me));
        free(me);
        if (verbose) {
            dropbear_log(LOG_INFO, MSG_PREFIX "Plugin deleted");
        }
    }
}

// }}}
// {{{ MyDeleteSession
// ----------------------------------------------------------------------------
static void MyDeleteSession(struct EPKASession *_session) {
    struct MySession *session = (struct MySession *)_session;

    if (session) {
        struct MyPlugin *me = (struct MyPlugin *)_session->plugin_instance;
        if (me->m_tableStatus) {
            sqlRunStatusUpdate(me, session, 0, 0);
        }
        if (me->m_tableLog) {
            sqlRunLogInsert(me, session, LOG_ENTRY_KEYWORD_DISCONNECTED);
        }
        if (session->m_options) {
            free(session->m_options);
        }
        if (session->m_username) {
            free(session->m_username);
        }
        if (session->m_keyblob) {
            free(session->m_keyblob);
        }
        if (session->m_clientId) {
            free(session->m_clientId);
        }
        free(session);
        memset(session, 0, sizeof(*session));
        if (me->m_verbose) {
            dropbear_log(LOG_DEBUG, MSG_PREFIX "Session_deleted");
        }
    }
}

// }}}
// {{{ MyCheckPubKey
// ----------------------------------------------------------------------------
static int MyCheckPubKey(struct EPKAInstance *instance, 
        struct EPKASession **sessionInOut,
        const char* algo, 
        unsigned int algolen,
        const unsigned char* keyblob, 
        unsigned int keybloblen,
        const char *username) {
    struct MyPlugin * me = (struct MyPlugin *)instance;
    struct MySession *retVal = (struct MySession *)*sessionInOut;
    char *dbPubkey = NULL;
    unsigned int dbPubkeyLen = 0;
    char *dbOptions  = NULL;
    char *dbClientId = NULL;
    int ok = 0;

    if (!retVal) {
        // Pre-auth: runs the query
        if (!sqlRunQueryAuth(me, algo, algolen, keyblob, keybloblen, username, &dbClientId, &dbOptions, &dbPubkey, &dbPubkeyLen)) {
            // Error running the query
            dropbear_log(LOG_ERR, MSG_PREFIX "error running database query for auth");
            goto err;
        }
        if (!dbPubkey) {
            // Auth failed
            if (me->m_verbose) {
                dropbear_log(LOG_DEBUG, MSG_PREFIX "no matching entry for user '%s'", username);
            }
            goto err;
        }

        /* Create a new session */
        retVal = calloc(1, sizeof(*retVal));
        if (!retVal) {
            goto err;
        }

        retVal->m_parent.plugin_instance = instance;
        retVal->m_parent.get_options = MyGetOptions;

        retVal->m_options = dbOptions;
        retVal->m_username = strdup(username);
        retVal->m_keyblob = dbPubkey;
        retVal->m_keybloblen = dbPubkeyLen;
        retVal->m_clientId = dbClientId;
        dbPubkey = NULL;        // Ownership of those pointers has been transferred
        dbOptions = NULL;       // to the session object. set it to NULL so in case
        dbClientId = NULL;      // of error from now on they won't be free'd twice
        *sessionInOut = &retVal->m_parent;
        if (me->m_verbose) {
            dropbear_log(LOG_DEBUG, MSG_PREFIX "User '%s' pre-auth success", username);
        }
    }
    // Session created or already present, (re)check key
    if (strcmp(username, retVal->m_username) != 0) {
        if (me->m_verbose) {
            dropbear_log(LOG_DEBUG, MSG_PREFIX "User '%s' auth mismatch", username);
        }
        goto err;
    }
    if ((keybloblen !=retVal->m_keybloblen) || (memcmp(keyblob, retVal->m_keyblob, keybloblen) != 0) ) {
        if (me->m_verbose) {
            dropbear_log(LOG_DEBUG, MSG_PREFIX "Pubkey auth mismatch", username);
        }
        goto err;
    }
    if (me->m_verbose) {
        dropbear_log(LOG_DEBUG, MSG_PREFIX "User '%s' auth validated", username);
    }
    return DROPBEAR_SUCCESS;

err:
    if (dbPubkey) {
        free(dbPubkey);
    }
    if (dbOptions) {
        free(dbOptions);
    }
    if (dbClientId) {
        free(dbClientId);
    }
    return DROPBEAR_FAILURE;
}

// }}}
// {{{ MyAuthSuccess
// ----------------------------------------------------------------------------
static void MyAuthSuccess(struct EPKASession *_session) {
    struct MySession *session = (struct MySession *)_session;
    struct MyPlugin *me = (struct MyPlugin *)_session->plugin_instance;

    if (!session->m_clientId) {
        if (me->m_verbose) {
            dropbear_log(LOG_DEBUG, MSG_PREFIX "missing clientID, skipping updating status and log table");
        }
        return;
    }

    if (me->m_tableStatus) {
        sqlRunStatusUpdate(me, session, 1, (int)getpid());
    }
    if (me->m_tableLog) {
        sqlRunLogInsert(me, session, LOG_ENTRY_KEYWORD_CONNECTED);
    }
}

// }}}


/* The plugin entry point */
void * plugin_new(int verbose, const char *configFile, const char *addrstring) {
    struct MyPlugin *retVal = NULL;

    if (!configFile) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Missing auth file from options");
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
    if (addrstring) {
        char *ptr;
        retVal->m_clientIp = strdup(addrstring);
        // Remove the port...
        ptr = strchr(retVal->m_clientIp, ':');
        if (ptr) *ptr='\0';
    }

    if (!initFromConfig(retVal, configFile)) {
        goto err;
    }

    if (verbose) {
        dropbear_log(LOG_DEBUG, MSG_PREFIX "Plugin initialized - config file = %s, clientIP=%s", configFile, addrstring);
    }
    return &retVal->m_parent;

err:
    if (retVal) {
        MyDeletePlugin(&retVal->m_parent);
    }
    return NULL;
}



