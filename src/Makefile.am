lib_LTLIBRARIES=libepka_test.la libepka_file.la

if EPKA_BUILD_MYSQL
lib_LTLIBRARIES += libepka_mysql.la
libepka_mysql_la_SOURCES=mysqlauth.c ../ext/cJSON.c common.c
libepka_mysql_la_CFLAGS=-fPIC -I ../ext
libepka_mysql_la_LDFLAGS= -shared -module -export-dynamic -version-info 1:0:0

endif

libepka_test_la_SOURCES=testauth.c
libepka_test_la_CFLAGS=-fPIC
libepka_test_la_LDFLAGS= -shared -module -export-dynamic -version-info 1:0:0

libepka_file_la_SOURCES=fileauth.c ../ext/cJSON.c common.c
libepka_file_la_CFLAGS=-fPIC -I ../ext
libepka_file_la_LDFLAGS= -shared -module -export-dynamic -version-info 1:0:0

