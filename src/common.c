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



/* A collection of shared functions.
 * Taken from fablib (http://www.github.com/fabriziobertocci/fablib)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


/****************************************************************************/
/* UTILITIES                                                                */
/****************************************************************************/
/* {{{ getFileLength
 * -------------------------------------------------------------------------
 */
static int getFileLength(FILE *file, long *sizeOut, const char **errOut) {
    assert(file);
    assert(sizeOut);

    if (fseek(file, 0L, SEEK_END) < 0) {
        if (errOut) *errOut = "fseek (end) failed";
        return 0;
    }
    *sizeOut = ftell(file);
    if (*sizeOut < 0) {
        if (errOut) *errOut = "ftell failed";
        return 0;
    }
    if (fseek(file, 0L, SEEK_SET) < 0) {
        if (errOut) *errOut = "fseek (set) failed";
        return 0;
    }
    return 1;
}
/* }}} */
/* {{{ readFile
 * -------------------------------------------------------------------------
 */
int readFile(const char *path, char **bufInOut, long *sizeInOut, const char **errOut) {
    int ok = 0;
    FILE *f = NULL;
    int freeOnError = 0;
    long fileSize;

    assert(path);
    assert(bufInOut);
    assert(sizeInOut);

    f = fopen(path, "r");
    if (!f) {
        // Not found
        if (errOut) *errOut = "File not found";
        goto done;
    }

    if (!getFileLength(f, &fileSize, errOut)) {
        goto done;
    }
    if (*bufInOut) {
        // Read buffer is provided. Is it large enough?
        if ((fileSize + 1) > *sizeInOut) {        // The +1 is to allow an extra byte for the '\0'
            if (errOut) *errOut = "Buffer too small";
            goto done;
        }
    } else {
        // Read buffer not provided, validate the max size
        if (*sizeInOut > 0 && *sizeInOut < fileSize) {
            if (errOut) *errOut = "File too large";
            goto done;
        }

        *bufInOut = (char *)malloc((size_t)(fileSize+1)); // Allocate one extra byte and set it to zero
        if (!*bufInOut) {
            if (errOut) *errOut = "Out of memory";
            goto done;
        }
        freeOnError = 1;
    }

    if (fread(*bufInOut, 1, (size_t)fileSize, f) < (size_t)fileSize) {
        if (errOut) *errOut = "Read error";
        goto done;
    }

    (*bufInOut)[fileSize] = '\0';
    *sizeInOut = fileSize;

    // Success
    ok = 1;

done:
    if (f) {
        fclose(f);
    }
    if (!ok && freeOnError && *bufInOut) {
        free(*bufInOut);
        *bufInOut = NULL;
    }
    return ok;
}
/* }}} */


