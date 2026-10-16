# SPDX-License-Identifier: MIT

if(CONFIG_ALU40_BLE_RECOVERY)
  zephyr_library()
  zephyr_library_sources(src/ble_recovery.c)
endif()
