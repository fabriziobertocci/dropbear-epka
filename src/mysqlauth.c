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
 * "colClientId": ["client_id"] Name of the column that identify the client connecting to the server - REQUIRED
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

#define _GNU_SOURCE
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
 
    /* Database Information */
    char *                  m_dbHost;
    int                     m_dbPort;
    char *                  m_dbUser;
    char *                  m_dbPass;
    char *                  m_dbTableName;
    MYSQL *                 m_dbConn;
    // MYSQL_STMT *            m_authStmt;

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


// {{{ databaseConnect
// ----------------------------------------------------------------------------
// Returns 1 if success, 0 if an error occurred
static int databaseConnect(struct MyPlugin *me) {
    my_bool arg = 1;

    // Connect to database
    me->m_dbConn = mysql_init(NULL);
    if (!me->m_dbConn) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Database connection initialization failed");
        return 0;
    }

    if (mysql_options(me->m_dbConn, MYSQL_OPT_RECONNECT, &arg)) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Failed to set database reconnect option : %s", mysql_error(me->m_dbConn));
        return 0;
    }

    if (!mysql_real_connect(me->m_dbConn,
                me->m_dbHost,
                me->m_dbUser,
                me->m_dbPass,
                me->m_dbTableName,
                me->m_dbPort,
                NULL,                   // Unix socket
                0)) {                   // Client flags
        dropbear_log(LOG_ERR, MSG_PREFIX "Database connection failed: %s", mysql_error(me->m_dbConn));
        return 0;
    }
    return 1;

}

// }}}
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
            readProperty(me->m_configRoot, "dbHost", 1, NULL, &me->m_dbHost) &&
            readProperty(me->m_configRoot, "dbUser", 1, NULL, &me->m_dbUser) &&
            readProperty(me->m_configRoot, "dbPass", 1, NULL, &me->m_dbPass) &&
            readProperty(me->m_configRoot, "dbName", 1, NULL, &me->m_dbTableName) &&

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
    /* If unset, use the default 3306 */
    me->m_dbPort = val ? val->valueint : 3306;

    // Connect to database
    if (!databaseConnect(me)) {
        goto done;
    }

#if 0
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
#endif

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
    char *query = NULL;
    MYSQL_RES *res = NULL;
    MYSQL_ROW  row;
    my_ulonglong numRows;
    unsigned int numFields;
    unsigned long *fieldLengths;
    char *keyblobHex = NULL;

    if (me->m_verbose) {
        dropbear_log(LOG_DEBUG, MSG_PREFIX "Pre-auth, user '%s'...", username);
    }
    *clientIdOut = NULL;
    *optionsOut = NULL;
    *pubkeyOut = NULL;
    *pubkeyOutLen = 0;

    /* Ensure the connection with the server is still up */
    if (mysql_ping(me->m_dbConn)) {
        dropbear_log(LOG_ERR, MSG_PREFIX "MySQL server ping error: %s", mysql_error(me->m_dbConn));
        goto done;
    }

    /* First convert the keyblob to a hex form */
    keyblobHex = malloc(keybloblen * 2 + 1);
    if (!keyblobHex) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Out of memory allocating keyblobHex");
        goto done;
    }
    mysql_hex_string(keyblobHex, keyblob, keybloblen);

    rc = asprintf(&query, 
//               cli   opts  pubkey    table      user            keyform         keyhash
//               |     |     |         |          |               |               |
        "SELECT `%s`, `%s`, `%s` FROM `%s` WHERE `%s`=\"%s\" AND `%s`=\"%.*s\" AND `%s`=UNHEX(SHA2(X'%s', 256))",
//               |     |     |                        |          |                     |
//               r0    r1    r2                       q0         q1                    q2
            me->m_colClientId, 
            me->m_colAuthOptions,
            me->m_colAuthPubkey,
            me->m_tableAuth, 
            me->m_colAuthUser, 
            username,
            me->m_colAuthKeyform, 
            algolen,
            algo,
            me->m_colAuthKeyhash,
            keyblobHex);
    if (rc < 0) {
        dropbear_log(LOG_ERR, MSG_PREFIX  "Error composing auth query");
        goto done;
    }

    if (mysql_query(me->m_dbConn, query)) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Failed to run auth statement: %s",mysql_error(me->m_dbConn));
        if (me->m_verbose) {
            dropbear_log(LOG_ERR, MSG_PREFIX "query=%s", query);
        }
        goto done;
    }

    res = mysql_store_result(me->m_dbConn);
    if (!res) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Failed to get result set from auth query: %s",mysql_error(me->m_dbConn));
        goto done;
    }

    /* Expected one row */
    numRows = mysql_num_rows(res);
    if (numRows == 0) {
        if (me->m_verbose) {
            dropbear_log(LOG_DEBUG, MSG_PREFIX "Non matching entries");
        }
        ok = 1;
        goto done;
    }
    if (numRows > 1) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Unexpected number of results for auth query (%llu): %s", numRows, mysql_error(me->m_dbConn));
        goto done;
    }

    /* Expect 3 fields: cli, opts, pubkey */
    numFields = mysql_num_fields(res);
    if (numFields != 3) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Unexpected number of fields for auth query (%d): %s", numFields, mysql_error(me->m_dbConn));
        goto done;
    }

    row = mysql_fetch_row(res);
    if (!row) {
        dropbear_log(LOG_ERR, MSG_PREFIX "Unexpected fetch_row failed in auth query: %s", mysql_error(me->m_dbConn));
        goto done;
    }
    fieldLengths = mysql_fetch_lengths(res);

    /* client can be NULL */
    if (row[0]) {
        *clientIdOut = calloc(fieldLengths[0]+1, 1);
        if (!*clientIdOut) {
            dropbear_log(LOG_CRIT, MSG_PREFIX "Out of memory allocating client ID (size=%d)", fieldLengths[0]);
            goto done;
        }
        memcpy(*clientIdOut, row[0], fieldLengths[0]);
    }

    /* options can be NULL */
    if (row[1]) {
        *optionsOut = calloc(fieldLengths[1]+1, 1);
        if (!*optionsOut) {
            dropbear_log(LOG_CRIT, MSG_PREFIX "Out of memory allocating options (size=%d)", fieldLengths[1]);
            goto done;
        }
        memcpy(*optionsOut, row[1], fieldLengths[1]);
    }

    /* pubkey cannot be NULL */
    if (row[2]) {
        *pubkeyOut = malloc(fieldLengths[2]);
        if (!*pubkeyOut) {
            dropbear_log(LOG_CRIT, MSG_PREFIX "Out of memory allocating pubkey (size=%d)", fieldLengths[2]);
            goto done;
        }
        memcpy(*pubkeyOut, row[2], fieldLengths[2]);
        *pubkeyOutLen = fieldLengths[2];
    } else {
        dropbear_log(LOG_ERR, MSG_PREFIX "Unexpected NULL pubkey in auth query");
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
    if (res) {
        mysql_free_result(res);
    }
    if (query) {
        free(query);
    }
    if (keyblobHex) {
        free(keyblobHex);
    }
    return ok;
}

// }}}
// {{{ sqlRunStatusUpdate
// ----------------------------------------------------------------------------
// Returns 1 if the query was executed successfully, 0 if an error occurred or
// the query was skipped
int sqlRunStatusUpdate(struct MyPlugin *me, struct MySession *session, int statusInt, int pid) {
    char * query = NULL;
    int ok = 0;

    /* Ensure the connection with the server is still up */
    if (mysql_ping(me->m_dbConn)) {
        dropbear_log(LOG_ERR, MSG_PREFIX "MySQL server ping error: %s", mysql_error(me->m_dbConn));
        goto done;
    }

    if (asprintf(&query,
//               table    conn  1/0  pid   xxx  addr   IP          cliId   val
//               |        |     |    |     |    |      |           |       |
        "UPDATE `%s` SET `%s` = %d, `%s` = %d, `%s` = \"%s\" WHERE `%s` = \"%s\"",
            me->m_tableStatus,
            me->m_colStatusConnected, statusInt,
            me->m_colStatusPid, pid,
            me->m_colStatusAddress, (me->m_clientIp ? me->m_clientIp : ""),
            me->m_colClientId, session->m_clientId) < 0) {
        dropbear_log(LOG_ERR, MSG_PREFIX  "Error composing statusUpdate query");
        goto done;
    }

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

done:
    if (query) {
        free(query);
    }
    return ok;
}

// }}}
// {{{ sqlRunLogInsert
// ----------------------------------------------------------------------------
// Returns 1 if the query was executed successfully, 0 if an error occurred or
// the query was skipped
int sqlRunLogInsert(struct MyPlugin *me, struct MySession *session, const char *evt) {
    char * query = NULL;
    int ok = 0;

    /* Ensure the connection with the server is still up */
    if (mysql_ping(me->m_dbConn)) {
        dropbear_log(LOG_ERR, MSG_PREFIX "MySQL server ping error: %s", mysql_error(me->m_dbConn));
        goto done;
    }

    if (asprintf(&query,
//                    table cli   ts    event          cli            event
//                    |     |     |     |              |              |
        "INSERT INTO `%s` (`%s`, `%s`, `%s`) VALUES (\"%s\", now(), \"%s\")",
            me->m_tableLog,
            me->m_colClientId,
            me->m_colLogTs,
            me->m_colLogEvent,
            session->m_clientId, evt) < 0) {
        dropbear_log(LOG_ERR, MSG_PREFIX  "Error composing logInsert query");
        goto done;
    }

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

done:
    if (query) {
        free(query);
    }
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
        /*
        if (me->m_authStmt) {
            mysql_stmt_close(me->m_authStmt);
            me->m_authStmt = NULL;
        }
        */
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
        dropbear_log(LOG_DEBUG, MSG_PREFIX "Client pre-auth success: %s:%s", username, retVal->m_clientId);
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



