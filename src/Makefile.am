lib_LTLIBRARIES=libepka_test.la libepka_file.la

libepka_test_la_SOURCES=testauth.c
libepka_test_la_CFLAGS=-fPIC
libepka_test_la_LDFLAGS= -shared -module -export-dynamic -version-info 1:0:0

libepka_file_la_SOURCES=fileauth.c ../ext/cJSON.c common.c
libepka_file_la_CFLAGS=-fPIC -I ../ext
libepka_file_la_LDFLAGS= -shared -module -export-dynamic -version-info 1:0:0
