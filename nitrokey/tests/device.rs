// Copyright (C) 2018-2019 Robin Krahl <robin.krahl@ireas.org>
// SPDX-License-Identifier: MIT

mod util;

use std::ffi::CStr;
use std::process::Command;
use std::{thread, time};

use nitrokey::{
    Authenticate, CommandError, CommunicationError, Config, ConfigureOtp, Device, Error,
    GenerateOtp, GetPasswordSafe, LibraryError, OtpMode, OtpSlotData, Storage, VolumeMode,
};
use nitrokey_test::test as test_device;

use crate::util::{ADMIN_PASSWORD, USER_PASSWORD};

static ADMIN_NEW_PASSWORD: &str = "1234567890";
static UPDATE_PIN: &str = "12345678";
static UPDATE_NEW_PIN: &str = "87654321";
static USER_NEW_PASSWORD: &str = "abcdefghij";

fn count_nitrokey_block_devices() -> usize {
    thread::sleep(time::Duration::from_secs(2));
    let output = Command::new("lsblk")
        .args(&["-o", "MODEL"])
        .output()
        .expect("Could not list block devices");
    String::from_utf8_lossy(&output.stdout)
        .split("\n")
        .filter(|&s| s.replace("_", " ") == "Nitrokey Storage")
        .count()
}

#[test_device]
fn connect_no_device() {
    assert_cmu_err!(CommunicationError::NotConnected, nitrokey::connect());
    assert_cmu_err!(
        CommunicationError::NotConnected,
        nitrokey::connect_model(nitrokey::Model::Pro)
    );
    assert_cmu_err!(
        CommunicationError::NotConnected,
        nitrokey::connect_model(nitrokey::Model::Storage)
    );
    assert_cmu_err!(CommunicationError::NotConnected, nitrokey::Pro::connect());
    assert_cmu_err!(
        CommunicationError::NotConnected,
        nitrokey::Storage::connect()
    );
}

#[test_device]
fn connect_pro(device: Pro) {
    assert_eq!(device.get_model(), nitrokey::Model::Pro);
    drop(device);

    assert_any_ok!(nitrokey::connect());
    assert_any_ok!(nitrokey::connect_model(nitrokey::Model::Pro));
    assert_any_ok!(nitrokey::Pro::connect());
}

#[test_device]
fn connect_storage(device: Storage) {
    assert_eq!(device.get_model(), nitrokey::Model::Storage);
    drop(device);

    assert_any_ok!(nitrokey::connect());
    assert_any_ok!(nitrokey::connect_model(nitrokey::Model::Storage));
    assert_any_ok!(nitrokey::Storage::connect());
}

fn assert_empty_serial_number() {
    unsafe {
        let ptr = nitrokey_sys::NK_device_serial_number();
        assert!(!ptr.is_null());
        let cstr = CStr::from_ptr(ptr);
        assert_eq!(cstr.to_string_lossy(), "");
    }
}

#[test_device]
fn disconnect(device: DeviceWrapper) {
    drop(device);
    assert_empty_serial_number();
}

#[test_device]
fn get_serial_number(device: DeviceWrapper) {
    let serial_number = unwrap_ok!(device.get_serial_number());
    assert!(serial_number.is_ascii());
    assert!(serial_number.chars().all(|c| c.is_ascii_hexdigit()));
}
#[test_device]
fn get_firmware_version(device: Pro) {
    let version = unwrap_ok!(device.get_firmware_version());
    assert_eq!(0, version.major);
    assert!(version.minor > 0);
}

fn admin_retry<T: Authenticate + Device>(device: &mut T, suffix: &str, count: u8) {
    assert_any_ok!(device.authenticate_admin(&(ADMIN_PASSWORD.to_owned() + suffix)));
    assert_ok!(count, device.get_admin_retry_count());
}

fn user_retry<T: Authenticate + Device>(device: &mut T, suffix: &str, count: u8) {
    assert_any_ok!(device.authenticate_user(&(USER_PASSWORD.to_owned() + suffix)));
    assert_ok!(count, device.get_user_retry_count());
}

#[test_device]
fn get_retry_count(device: DeviceWrapper) {
    let mut device = device;

    admin_retry(&mut device, "", 3);
    admin_retry(&mut device, "123", 2);
    admin_retry(&mut device, "456", 1);
    admin_retry(&mut device, "", 3);

    user_retry(&mut device, "", 3);
    user_retry(&mut device, "123", 2);
    user_retry(&mut device, "456", 1);
    user_retry(&mut device, "", 3);
}

#[test_device]
fn config(device: DeviceWrapper) {
    let mut device = device;
    let mut admin = unwrap_ok!(device.authenticate_admin(ADMIN_PASSWORD));

    let config = Config::new(None, None, None, true);
    assert_ok!((), admin.write_config(config));
    assert_ok!(config, admin.get_config());

    let config = Config::new(None, Some(9), None, true);
    assert_lib_err!(LibraryError::InvalidSlot, admin.write_config(config));

    let config = Config::new(Some(1), None, Some(0), false);
    assert_ok!((), admin.write_config(config));
    assert_ok!(config, admin.get_config());

    let config = Config::new(None, None, None, false);
    assert_ok!((), admin.write_config(config));
    assert_ok!(config, admin.get_config());
}

#[test_device]
fn change_user_pin(device: DeviceWrapper) {
    let mut device = device;
    assert_any_ok!(device.authenticate_user(USER_PASSWORD));
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.authenticate_user(USER_NEW_PASSWORD)
    );

    assert_ok!((), device.change_user_pin(USER_PASSWORD, USER_NEW_PASSWORD));

    assert_cmd_err!(
        CommandError::WrongPassword,
        device.authenticate_user(USER_PASSWORD)
    );
    assert_any_ok!(device.authenticate_user(USER_NEW_PASSWORD));

    let result = device.change_user_pin(USER_PASSWORD, USER_PASSWORD);
    assert_cmd_err!(CommandError::WrongPassword, result);

    assert_ok!((), device.change_user_pin(USER_NEW_PASSWORD, USER_PASSWORD));

    assert_any_ok!(device.authenticate_user(USER_PASSWORD));
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.authenticate_user(USER_NEW_PASSWORD)
    );
}

#[test_device]
fn change_admin_pin(device: DeviceWrapper) {
    let mut device = device;
    assert_any_ok!(device.authenticate_admin(ADMIN_PASSWORD));
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.authenticate_admin(ADMIN_NEW_PASSWORD)
    );

    assert_ok!(
        (),
        device.change_admin_pin(ADMIN_PASSWORD, ADMIN_NEW_PASSWORD)
    );

    assert_cmd_err!(
        CommandError::WrongPassword,
        device.authenticate_admin(ADMIN_PASSWORD)
    );
    assert_any_ok!(device.authenticate_admin(ADMIN_NEW_PASSWORD));

    assert_cmd_err!(
        CommandError::WrongPassword,
        device.change_admin_pin(ADMIN_PASSWORD, ADMIN_PASSWORD)
    );

    assert_ok!(
        (),
        device.change_admin_pin(ADMIN_NEW_PASSWORD, ADMIN_PASSWORD)
    );

    assert_any_ok!(device.authenticate_admin(ADMIN_PASSWORD));
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.authenticate_admin(ADMIN_NEW_PASSWORD)
    );
}

fn require_failed_user_login<D: Authenticate + Device>(device: &mut D, password: &str) {
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.authenticate_user(password)
    );
}

#[test_device]
fn unlock_user_pin(device: DeviceWrapper) {
    let mut device = device;
    assert_any_ok!(device.authenticate_user(USER_PASSWORD));
    assert_ok!((), device.unlock_user_pin(ADMIN_PASSWORD, USER_PASSWORD));
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.unlock_user_pin(USER_PASSWORD, USER_PASSWORD)
    );

    // block user PIN
    let wrong_password = USER_PASSWORD.to_owned() + "foo";
    require_failed_user_login(&mut device, &wrong_password);
    require_failed_user_login(&mut device, &wrong_password);
    require_failed_user_login(&mut device, &wrong_password);
    require_failed_user_login(&mut device, USER_PASSWORD);

    // unblock with current PIN
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.unlock_user_pin(USER_PASSWORD, USER_PASSWORD)
    );
    assert_ok!((), device.unlock_user_pin(ADMIN_PASSWORD, USER_PASSWORD));
    assert_any_ok!(device.authenticate_user(USER_PASSWORD));

    // block user PIN
    require_failed_user_login(&mut device, &wrong_password);
    require_failed_user_login(&mut device, &wrong_password);
    require_failed_user_login(&mut device, &wrong_password);
    require_failed_user_login(&mut device, USER_PASSWORD);

    // unblock with new PIN
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.unlock_user_pin(USER_PASSWORD, USER_PASSWORD)
    );
    assert_ok!(
        (),
        device.unlock_user_pin(ADMIN_PASSWORD, USER_NEW_PASSWORD)
    );

    // reset user PIN
    assert_ok!((), device.change_user_pin(USER_NEW_PASSWORD, USER_PASSWORD));
}

fn assert_utf8_err_or_ne(left: &str, right: Result<String, Error>) {
    match right {
        Ok(s) => assert_ne!(left.to_string(), s),
        Err(Error::Utf8Error(_)) => {}
        Err(err) => panic!("Expected Utf8Error, got {}!", err),
    }
}

#[test_device]
fn factory_reset(device: DeviceWrapper) {
    let mut device = device;
    let mut admin = unwrap_ok!(device.authenticate_admin(ADMIN_PASSWORD));
    let otp_data = OtpSlotData::new(1, "test", "0123468790", OtpMode::SixDigits);
    assert_ok!((), admin.write_totp_slot(otp_data, 30));

    let mut pws = unwrap_ok!(device.get_password_safe(USER_PASSWORD));
    assert_ok!((), pws.write_slot(0, "test", "testlogin", "testpw"));
    drop(pws);

    assert_ok!((), device.change_user_pin(USER_PASSWORD, USER_NEW_PASSWORD));
    assert_ok!(
        (),
        device.change_admin_pin(ADMIN_PASSWORD, ADMIN_NEW_PASSWORD)
    );

    assert_cmd_err!(
        CommandError::WrongPassword,
        device.factory_reset(USER_NEW_PASSWORD)
    );
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.factory_reset(ADMIN_PASSWORD)
    );
    assert_ok!((), device.factory_reset(ADMIN_NEW_PASSWORD));

    assert_any_ok!(device.authenticate_admin(ADMIN_PASSWORD));

    let user = unwrap_ok!(device.authenticate_user(USER_PASSWORD));
    assert_cmd_err!(CommandError::SlotNotProgrammed, user.get_totp_slot_name(1));

    let pws = unwrap_ok!(device.get_password_safe(USER_PASSWORD));
    assert_utf8_err_or_ne("test", pws.get_slot_name(0));
    assert_utf8_err_or_ne("testlogin", pws.get_slot_login(0));
    assert_utf8_err_or_ne("testpw", pws.get_slot_password(0));
    drop(pws);

    assert_ok!((), device.build_aes_key(ADMIN_PASSWORD));
}

#[test_device]
fn build_aes_key(device: DeviceWrapper) {
    let mut device = device;
    let mut pws = unwrap_ok!(device.get_password_safe(USER_PASSWORD));
    assert_ok!((), pws.write_slot(0, "test", "testlogin", "testpw"));
    drop(pws);

    assert_cmd_err!(
        CommandError::WrongPassword,
        device.build_aes_key(USER_PASSWORD)
    );
    assert_ok!((), device.build_aes_key(ADMIN_PASSWORD));

    assert_any_ok!(device.authenticate_admin(ADMIN_PASSWORD));

    let pws = unwrap_ok!(device.get_password_safe(USER_PASSWORD));
    assert_utf8_err_or_ne("test", pws.get_slot_name(0));
    assert_utf8_err_or_ne("testlogin", pws.get_slot_login(0));
    assert_utf8_err_or_ne("testpw", pws.get_slot_password(0));
}

#[test_device]
fn change_update_pin(device: Storage) {
    let mut device = device;
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.change_update_pin(UPDATE_NEW_PIN, UPDATE_PIN)
    );
    assert_ok!((), device.change_update_pin(UPDATE_PIN, UPDATE_NEW_PIN));
    assert_ok!((), device.change_update_pin(UPDATE_NEW_PIN, UPDATE_PIN));
}

#[test_device]
fn encrypted_volume(device: Storage) {
    let mut device = device;
    assert_ok!((), device.lock());

    assert_eq!(1, count_nitrokey_block_devices());
    assert_ok!((), device.disable_encrypted_volume());
    assert_eq!(1, count_nitrokey_block_devices());
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.enable_encrypted_volume("123")
    );
    assert_eq!(1, count_nitrokey_block_devices());
    assert_ok!((), device.enable_encrypted_volume(USER_PASSWORD));
    assert_eq!(2, count_nitrokey_block_devices());
    assert_ok!((), device.disable_encrypted_volume());
    assert_eq!(1, count_nitrokey_block_devices());
}

#[test_device]
fn hidden_volume(device: Storage) {
    let mut device = device;
    assert_ok!((), device.lock());

    assert_eq!(1, count_nitrokey_block_devices());
    assert_ok!((), device.disable_hidden_volume());
    assert_eq!(1, count_nitrokey_block_devices());

    assert_ok!((), device.enable_encrypted_volume(USER_PASSWORD));
    assert_eq!(2, count_nitrokey_block_devices());

    // TODO: why this error code?
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.create_hidden_volume(5, 0, 100, "hiddenpw")
    );
    assert_ok!((), device.create_hidden_volume(0, 20, 21, "hidden-pw"));
    assert_ok!((), device.create_hidden_volume(0, 20, 21, "hiddenpassword"));
    assert_ok!((), device.create_hidden_volume(1, 0, 1, "otherpw"));
    // TODO: test invalid range (not handled by libnitrokey)
    assert_eq!(2, count_nitrokey_block_devices());

    assert_cmd_err!(
        CommandError::WrongPassword,
        device.enable_hidden_volume("blubb")
    );
    assert_ok!((), device.enable_hidden_volume("hiddenpassword"));
    assert_eq!(2, count_nitrokey_block_devices());
    assert_ok!((), device.enable_hidden_volume("otherpw"));
    assert_eq!(2, count_nitrokey_block_devices());

    assert_ok!((), device.disable_hidden_volume());
    assert_eq!(1, count_nitrokey_block_devices());
}

#[test_device]
fn lock(device: Storage) {
    let mut device = device;
    assert_ok!((), device.enable_encrypted_volume(USER_PASSWORD));
    assert_ok!((), device.lock());
    assert_eq!(1, count_nitrokey_block_devices());
}

#[test_device]
fn set_encrypted_volume_mode(device: Storage) {
    // This test case does not check the device status as the command only works with firmware
    // version 0.49.  For later versions, it does not do anything and always returns Ok(()).
    let mut device = device;

    assert_ok!(
        (),
        device.set_encrypted_volume_mode(ADMIN_PASSWORD, VolumeMode::ReadOnly)
    );

    // TODO: re-enable once the password is checked in the firmware
    // assert_cmd_err!(
    //     CommandError::WrongPassword,
    //     device.set_encrypted_volume_mode(USER_PASSWORD, VolumeMode::ReadOnly)
    // );

    assert_ok!(
        (),
        device.set_encrypted_volume_mode(ADMIN_PASSWORD, VolumeMode::ReadOnly)
    );
    assert_ok!(
        (),
        device.set_encrypted_volume_mode(ADMIN_PASSWORD, VolumeMode::ReadWrite)
    );
    assert_ok!(
        (),
        device.set_encrypted_volume_mode(ADMIN_PASSWORD, VolumeMode::ReadOnly)
    );
}

#[test_device]
fn set_unencrypted_volume_mode(device: Storage) {
    fn assert_mode(device: &Storage, mode: VolumeMode) {
        let status = unwrap_ok!(device.get_status());
        assert_eq!(
            status.unencrypted_volume.read_only,
            mode == VolumeMode::ReadOnly
        );
    }

    fn assert_success(device: &mut Storage, mode: VolumeMode) {
        assert_ok!((), device.set_unencrypted_volume_mode(ADMIN_PASSWORD, mode));
        assert_mode(&device, mode);
    }

    let mut device = device;
    assert_success(&mut device, VolumeMode::ReadOnly);

    assert_cmd_err!(
        CommandError::WrongPassword,
        device.set_unencrypted_volume_mode(USER_PASSWORD, VolumeMode::ReadOnly)
    );
    assert_mode(&device, VolumeMode::ReadOnly);

    assert_success(&mut device, VolumeMode::ReadWrite);
    assert_success(&mut device, VolumeMode::ReadWrite);
    assert_success(&mut device, VolumeMode::ReadOnly);
}

#[test_device]
fn get_storage_status(device: Storage) {
    let status = unwrap_ok!(device.get_status());
    assert!(status.serial_number_sd_card > 0);
    assert!(status.serial_number_smart_card > 0);
}

#[test_device]
fn get_production_info(device: Storage) {
    let info = unwrap_ok!(device.get_production_info());
    assert_eq!(0, info.firmware_version.major);
    assert!(info.firmware_version.minor != 0);
    assert!(info.serial_number_cpu != 0);
    assert!(info.sd_card.serial_number != 0);
    assert!(info.sd_card.size > 0);
    assert!(info.sd_card.manufacturing_year > 10);
    assert!(info.sd_card.manufacturing_year < 100);
    // TODO: month value is not valid atm
    // assert!(info.sd_card.manufacturing_month < 12);
    assert!(info.sd_card.oem != 0);
    assert!(info.sd_card.manufacturer != 0);

    let status = unwrap_ok!(device.get_status());
    assert_eq!(status.firmware_version, info.firmware_version);
    assert_eq!(status.serial_number_sd_card, info.sd_card.serial_number);
}

#[test_device]
fn clear_new_sd_card_warning(device: Storage) {
    let mut device = device;
    assert_ok!((), device.factory_reset(ADMIN_PASSWORD));
    thread::sleep(time::Duration::from_secs(3));
    assert_ok!((), device.build_aes_key(ADMIN_PASSWORD));

    // We have to perform an SD card operation to reset the new_sd_card_found field
    assert_ok!((), device.lock());

    let status = unwrap_ok!(device.get_status());
    assert!(status.new_sd_card_found);

    assert_ok!((), device.clear_new_sd_card_warning(ADMIN_PASSWORD));

    let status = unwrap_ok!(device.get_status());
    assert!(!status.new_sd_card_found);
}

#[test_device]
fn export_firmware(device: Storage) {
    let mut device = device;
    assert_cmd_err!(
        CommandError::WrongPassword,
        device.export_firmware("someadminpn")
    );
    assert_ok!((), device.export_firmware(ADMIN_PASSWORD));
    assert_ok!(
        (),
        device.set_unencrypted_volume_mode(ADMIN_PASSWORD, VolumeMode::ReadWrite)
    );
    assert_ok!((), device.export_firmware(ADMIN_PASSWORD));
    assert_ok!(
        (),
        device.set_unencrypted_volume_mode(ADMIN_PASSWORD, VolumeMode::ReadOnly)
    );
}
