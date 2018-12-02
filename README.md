# dropbear-epka
A collection of External Public-Key Authentication (EPKA) plug-ins for Dropbear

----------------------
## Dropbear Integration
You need to compile dropbear with the ```--enable-epka``` option.
When you define this flag:

* The macro ```DROPBEAR_EPKA``` is set to 1 and enable code that is usually #ifdef'd out

* Code is compiled to enable the external plug-in at run-time through command-line argument ```-A <pluginName>[,pluginOptions]```.
  The ```pluginName``` is the full path of the shared library of the plug-in. 
  ```pluginOptions``` is an optional string that is passed as is to the plug-in.
  Separate the plugin name from the options using a comma.


If ```-A``` argument is specified:

* A plug-in instance is created when a new server session is created (when a client connects)

* Pubkey authentication is then attempted through the plug-in. 
  If the plug-in fails to authenticate the given user, dropbear will still try to authenticate
  using public key through the ```~/.ssh/authorized_keys``` file.

* During pre-auth, the plug-in creates an ssh session. The plug-in can use the session
  to cache any information about the pre-authenticated user.

* After authentication is completed, the plug-in is notified of the successful operation. 
  The plug-in can use this callback to perform some action when a client log in.

* When the client disconnects, dropbear will call into the plug-in to delete the session. 
  The plug-in can also use this callback to perfom some action when the client disconnect.

--------------------
## What should I do with it?
Currently dropbear (and even ssh, except for some limited cases) can only read the list of authorized keys from a non-configurable file (```~/.ssh/authorized_keys```).

With OpenSSH you can use the configuration ```AuthorizedKeysCommand``` to invoke a comand to produce the content of the ```authorized_keys``` file, but there are still limitations on the ability to perform 
custom operations when a client log in or disconnect.

If you need more flexibility, and/or do something when a client connect or disconnect, you can create your own plug-in and use it with dropbear without the need to modify dropbear itself.

The concept of this interface is similar to [PAM](https://en.wikipedia.org/wiki/Pluggable_authentication_module)

These are few examples on what you can do with this interface:

* Read the public keys from a custom file (different than ~/.ssh/keys_authorized)
* Allow/deny access to a system depending on other external factors (i.e. you can reject all the clients except for one between a certain time window)
* Notify an external application (do something) when a client connect
* Notify an external application (do something) when the client disconnect
* Read the public keys from an external relational database
* Write into the database the state of the authenticated client


------------------
## API
The shared library need to export only a single function "plugin_new":

```c
struct EPKAInstance *plugin_new(
	int verbose,
	const char *options)
```
Where arguments are:

* ```verbose```: dropbear will set it to 1 if compiled with ```DEBUG_TRACE``` and the user invokes dropbear with the ```-v``` argument
* ```options```: dropbear will parse the value of the ```-A``` argument, and if an optional parameter is passed, it will be passed to the plugin here.

If the plug-in initialization is successful it will return an object that extends the base class ```EPKAInstance```.

The ```EPKAInstance``` base class contains function pointers that dropbear will use to call during the authentication sequence.

It is defined as:

```c
struct EPKAInstance {
    int                             api_version[2];         /* 0=Major, 1=Minor */

    PubkeyExtPlugin_checkPubKeyFn   checkpubkey;            /* mandatory */
    PubkeyExtPlugin_authSuccessFn   auth_success;           /* optional */
    PubkeyExtPlugin_sessionDeleteFn delete_session;         /* mandatory */
    PubkeyExtPlugin_deleteFn        delete_plugin;          /* mandatory */
};
```

Refer to the ```pubkeyapi.h``` file for additional information on the above functions.

------------------
## Examples

This project contains the following plug-ins:

### 1. ```testuth.c```
A simple plug-in that just authenticate ALL the clients (!!!) do NOT use it in any production system... actually no, don't use it on ANY system at all... 
but use it to see how the API works, or a starting point for your plug-in.


### 2.```fileauth.c```
A bit safer plug-in that reads a database of users and public keys from a single JSON file specified in the ```pluginOptions```.
Use it like this:

```
dropbear [...] -A lib/libepka_file.so,/opt/test/etc/epka-file.json
```

An example of the JSON file is:

```
[
    {
        "user": "fabrizio",
        "keytype": "ssh-rsa",
        "key": "AAAAB3NzaC1yc2EAAAADAQABAAABAQCqZk0opTk....",
        "options":"no-X11-forwarding",
        "comments": "An invalid key"
    }
]
```

