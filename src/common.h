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


/****************************************************************************/
/* UTILITIES                                                                */
/****************************************************************************/
/* Returns 0 in case of error, 1 if success.
 * File size is returned in sizeOut.
 */
int getFileLength(FILE *file, long *sizeOut, const char **errOut);



/* Returns 0 if fails, 1 on success. Error reason is returned in the optional 
 * errOut.
 * Returned buffer must be released with free()
 */
int readFile(const char *path, char **bufInOut, long *sizeInOut, const char **errOut);


