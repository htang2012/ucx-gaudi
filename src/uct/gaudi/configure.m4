#
# Copyright (c) 2024, Habana Labs Ltd. an Intel Company
#

UCX_CHECK_GAUDI

AS_IF([test "x$gaudi_happy" = "xyes"], [uct_modules="${uct_modules}:gaudi"])

# Initialize Gaudi modules list
uct_gaudi_modules=""

# Add copy and ipc transports when Gaudi is available
AS_IF([test "x$gaudi_happy" = "xyes"], 
      [uct_gaudi_modules="${uct_gaudi_modules}:copy:ipc"])

AC_DEFINE_UNQUOTED([uct_gaudi_MODULES], ["${uct_gaudi_modules}"], [GAUDI loadable modules])

AC_CONFIG_FILES([src/uct/gaudi/Makefile
                 src/uct/gaudi/ucx-gaudi.pc])
