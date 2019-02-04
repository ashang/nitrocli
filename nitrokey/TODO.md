<!---
Copyright (C) 2019 Robin Krahl <robin.krahl@ireas.org>
SPDX-License-Identifier: MIT
-->

- Add support for the currently unsupported commands:
    - `NK_send_startup`
    - `NK_fill_SD_card_with_random_data`
    - `NK_get_SD_usage_data_as_string`
    - `NK_get_progress_bar_value`
    - `NK_list_devices_by_cpuID`
    - `NK_connect_with_ID`
- Clear passwords from memory.
- Lock password safe in `PasswordSafe::drop()` (see [nitrokey-storage-firmware
  issue 65][]).
- Disable creation of multiple password safes at the same time.
- Check timing in Storage tests.
- Consider restructuring `device::StorageStatus`.

[nitrokey-storage-firmware issue 65]: https://github.com/Nitrokey/nitrokey-storage-firmware/issues/65
