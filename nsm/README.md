# Go NSM API
Wrapper for Nitro Secure Module API for Golang. To compile a project with this library, use pkg-config. 

libnsm.pc allows you to specify the path to the libnsm library, so the library can be placed anywhere, and the path to lib must be specified in this file. See the examples.


### libnsm.pc
```pkg-cofnig
libdir=/path/to/dir/with/lib

Name: libnsm
Description: Nitro Secure Module API
Version: v0.4.0
Libs: -L${libdir} -lnsm
```

### Specify path to directory with .pc files
```
export PKG_CONFIG_PATH=/path/to/libnsm.pc:$PKG_CONFIG_PATH
```

<hr>
TODO: Describe functions and add examples