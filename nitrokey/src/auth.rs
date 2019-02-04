// Copyright (C) 2018-2019 Robin Krahl <robin.krahl@ireas.org>
// SPDX-License-Identifier: MIT

use std::ops;
use std::os::raw::c_char;
use std::os::raw::c_int;

use nitrokey_sys;

use crate::config::{Config, RawConfig};
use crate::device::{Device, DeviceWrapper, Pro, Storage};
use crate::error::Error;
use crate::otp::{ConfigureOtp, GenerateOtp, OtpMode, OtpSlotData, RawOtpSlotData};
use crate::util::{generate_password, get_command_result, get_cstring, result_from_string};

static TEMPORARY_PASSWORD_LENGTH: usize = 25;

/// Provides methods to authenticate as a user or as an admin using a PIN.  The authenticated
/// methods will consume the current device instance.  On success, they return the authenticated
/// device.  Otherwise, they return the current unauthenticated device and the error code.
pub trait Authenticate {
    /// Performs user authentication.  This method consumes the device.  If successful, an
    /// authenticated device is returned.  Otherwise, the current unauthenticated device and the
    /// error are returned.
    ///
    /// This method generates a random temporary password that is used for all operations that
    /// require user access.
    ///
    /// # Errors
    ///
    /// - [`InvalidString`][] if the provided user password contains a null byte
    /// - [`RngError`][] if the generation of the temporary password failed
    /// - [`WrongPassword`][] if the provided user password is wrong
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nitrokey::{Authenticate, DeviceWrapper, User};
    /// # use nitrokey::Error;
    ///
    /// fn perform_user_task(device: &User<DeviceWrapper>) {}
    /// fn perform_other_task(device: &DeviceWrapper) {}
    ///
    /// # fn try_main() -> Result<(), Error> {
    /// let mut device = nitrokey::connect()?;
    /// match device.authenticate_user("123456") {
    ///     Ok(user) => perform_user_task(&user),
    ///     Err(err) => eprintln!("Could not authenticate as user: {}", err),
    /// };
    /// perform_other_task(&device);
    /// #     Ok(())
    /// # }
    /// ```
    ///
    /// [`InvalidString`]: enum.LibraryError.html#variant.InvalidString
    /// [`RngError`]: enum.CommandError.html#variant.RngError
    /// [`WrongPassword`]: enum.CommandError.html#variant.WrongPassword
    fn authenticate_user(&mut self, password: &str) -> Result<User<'_, Self>, Error>
    where
        Self: Device + std::marker::Sized;

    /// Performs admin authentication.  This method consumes the device.  If successful, an
    /// authenticated device is returned.  Otherwise, the current unauthenticated device and the
    /// error are returned.
    ///
    /// This method generates a random temporary password that is used for all operations that
    /// require admin access.
    ///
    /// # Errors
    ///
    /// - [`InvalidString`][] if the provided admin password contains a null byte
    /// - [`RngError`][] if the generation of the temporary password failed
    /// - [`WrongPassword`][] if the provided admin password is wrong
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nitrokey::{Authenticate, Admin, DeviceWrapper};
    /// # use nitrokey::Error;
    ///
    /// fn perform_admin_task(device: &Admin<DeviceWrapper>) {}
    /// fn perform_other_task(device: &DeviceWrapper) {}
    ///
    /// # fn try_main() -> Result<(), Error> {
    /// let mut device = nitrokey::connect()?;
    /// match device.authenticate_admin("123456") {
    ///     Ok(admin) => perform_admin_task(&admin),
    ///     Err(err) => eprintln!("Could not authenticate as admin: {}", err),
    /// };
    /// perform_other_task(&device);
    /// #     Ok(())
    /// # }
    /// ```
    ///
    /// [`InvalidString`]: enum.LibraryError.html#variant.InvalidString
    /// [`RngError`]: enum.CommandError.html#variant.RngError
    /// [`WrongPassword`]: enum.CommandError.html#variant.WrongPassword
    fn authenticate_admin(&mut self, password: &str) -> Result<Admin<'_, Self>, Error>
    where
        Self: Device + std::marker::Sized;
}

trait AuthenticatedDevice<'a, T> {
    fn new(device: &'a mut T, temp_password: Vec<u8>) -> Self;

    fn temp_password_ptr(&self) -> *const c_char;
}

/// A Nitrokey device with user authentication.
///
/// To obtain an instance of this struct, use the [`authenticate_user`][] method from the
/// [`Authenticate`][] trait.  To get back to an unauthenticated device, use the [`device`][]
/// method.
///
/// [`Authenticate`]: trait.Authenticate.html
/// [`authenticate_admin`]: trait.Authenticate.html#method.authenticate_admin
/// [`device`]: #method.device
#[derive(Debug)]
pub struct User<'a, T: Device> {
    device: &'a mut T,
    temp_password: Vec<u8>,
}

/// A Nitrokey device with admin authentication.
///
/// To obtain an instance of this struct, use the [`authenticate_admin`][] method from the
/// [`Authenticate`][] trait.  To get back to an unauthenticated device, use the [`device`][]
/// method.
///
/// [`Authenticate`]: trait.Authenticate.html
/// [`authenticate_admin`]: trait.Authenticate.html#method.authenticate_admin
/// [`device`]: #method.device
#[derive(Debug)]
pub struct Admin<'a, T: Device> {
    device: &'a mut T,
    temp_password: Vec<u8>,
}

fn authenticate<'a, D, A, T>(device: &'a mut D, password: &str, callback: T) -> Result<A, Error>
where
    D: Device,
    A: AuthenticatedDevice<'a, D>,
    T: Fn(*const c_char, *const c_char) -> c_int,
{
    let temp_password = generate_password(TEMPORARY_PASSWORD_LENGTH)?;
    let password = get_cstring(password)?;
    let password_ptr = password.as_ptr();
    let temp_password_ptr = temp_password.as_ptr() as *const c_char;
    match callback(password_ptr, temp_password_ptr) {
        0 => Ok(A::new(device, temp_password)),
        rv => Err(Error::from(rv)),
    }
}

impl<'a, T: Device> ops::Deref for User<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.device
    }
}

impl<'a, T: Device> ops::DerefMut for User<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.device
    }
}

impl<'a, T: Device> GenerateOtp for User<'a, T> {
    fn get_hotp_code(&mut self, slot: u8) -> Result<String, Error> {
        result_from_string(unsafe {
            nitrokey_sys::NK_get_hotp_code_PIN(slot, self.temp_password_ptr())
        })
    }

    fn get_totp_code(&self, slot: u8) -> Result<String, Error> {
        result_from_string(unsafe {
            nitrokey_sys::NK_get_totp_code_PIN(slot, 0, 0, 0, self.temp_password_ptr())
        })
    }
}

impl<'a, T: Device> AuthenticatedDevice<'a, T> for User<'a, T> {
    fn new(device: &'a mut T, temp_password: Vec<u8>) -> Self {
        User {
            device,
            temp_password,
        }
    }

    fn temp_password_ptr(&self) -> *const c_char {
        self.temp_password.as_ptr() as *const c_char
    }
}

impl<'a, T: Device> ops::Deref for Admin<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.device
    }
}

impl<'a, T: Device> ops::DerefMut for Admin<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.device
    }
}

impl<'a, T: Device> Admin<'a, T> {
    /// Writes the given configuration to the Nitrokey device.
    ///
    /// # Errors
    ///
    /// - [`InvalidSlot`][] if the provided numlock, capslock or scrolllock slot is larger than two
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nitrokey::{Authenticate, Config};
    /// # use nitrokey::Error;
    ///
    /// # fn try_main() -> Result<(), Error> {
    /// let mut device = nitrokey::connect()?;
    /// let config = Config::new(None, None, None, false);
    /// match device.authenticate_admin("12345678") {
    ///     Ok(mut admin) => admin.write_config(config)?,
    ///     Err(err) => eprintln!("Could not authenticate as admin: {}", err),
    /// };
    /// #     Ok(())
    /// # }
    /// ```
    ///
    /// [`InvalidSlot`]: enum.LibraryError.html#variant.InvalidSlot
    pub fn write_config(&mut self, config: Config) -> Result<(), Error> {
        let raw_config = RawConfig::try_from(config)?;
        get_command_result(unsafe {
            nitrokey_sys::NK_write_config(
                raw_config.numlock,
                raw_config.capslock,
                raw_config.scrollock,
                raw_config.user_password,
                false,
                self.temp_password_ptr(),
            )
        })
    }
}

impl<'a, T: Device> ConfigureOtp for Admin<'a, T> {
    fn write_hotp_slot(&mut self, data: OtpSlotData, counter: u64) -> Result<(), Error> {
        let raw_data = RawOtpSlotData::new(data)?;
        get_command_result(unsafe {
            nitrokey_sys::NK_write_hotp_slot(
                raw_data.number,
                raw_data.name.as_ptr(),
                raw_data.secret.as_ptr(),
                counter,
                raw_data.mode == OtpMode::EightDigits,
                raw_data.use_enter,
                raw_data.use_token_id,
                raw_data.token_id.as_ptr(),
                self.temp_password_ptr(),
            )
        })
    }

    fn write_totp_slot(&mut self, data: OtpSlotData, time_window: u16) -> Result<(), Error> {
        let raw_data = RawOtpSlotData::new(data)?;
        get_command_result(unsafe {
            nitrokey_sys::NK_write_totp_slot(
                raw_data.number,
                raw_data.name.as_ptr(),
                raw_data.secret.as_ptr(),
                time_window,
                raw_data.mode == OtpMode::EightDigits,
                raw_data.use_enter,
                raw_data.use_token_id,
                raw_data.token_id.as_ptr(),
                self.temp_password_ptr(),
            )
        })
    }

    fn erase_hotp_slot(&mut self, slot: u8) -> Result<(), Error> {
        get_command_result(unsafe {
            nitrokey_sys::NK_erase_hotp_slot(slot, self.temp_password_ptr())
        })
    }

    fn erase_totp_slot(&mut self, slot: u8) -> Result<(), Error> {
        get_command_result(unsafe {
            nitrokey_sys::NK_erase_totp_slot(slot, self.temp_password_ptr())
        })
    }
}

impl<'a, T: Device> AuthenticatedDevice<'a, T> for Admin<'a, T> {
    fn new(device: &'a mut T, temp_password: Vec<u8>) -> Self {
        Admin {
            device,
            temp_password,
        }
    }

    fn temp_password_ptr(&self) -> *const c_char {
        self.temp_password.as_ptr() as *const c_char
    }
}

impl Authenticate for DeviceWrapper {
    fn authenticate_user(&mut self, password: &str) -> Result<User<'_, Self>, Error> {
        authenticate(self, password, |password_ptr, temp_password_ptr| unsafe {
            nitrokey_sys::NK_user_authenticate(password_ptr, temp_password_ptr)
        })
    }

    fn authenticate_admin(&mut self, password: &str) -> Result<Admin<'_, Self>, Error> {
        authenticate(self, password, |password_ptr, temp_password_ptr| unsafe {
            nitrokey_sys::NK_user_authenticate(password_ptr, temp_password_ptr)
        })
    }
}

impl Authenticate for Pro {
    fn authenticate_user(&mut self, password: &str) -> Result<User<'_, Self>, Error> {
        authenticate(self, password, |password_ptr, temp_password_ptr| unsafe {
            nitrokey_sys::NK_user_authenticate(password_ptr, temp_password_ptr)
        })
    }

    fn authenticate_admin(&mut self, password: &str) -> Result<Admin<'_, Self>, Error> {
        authenticate(self, password, |password_ptr, temp_password_ptr| unsafe {
            nitrokey_sys::NK_first_authenticate(password_ptr, temp_password_ptr)
        })
    }
}

impl Authenticate for Storage {
    fn authenticate_user(&mut self, password: &str) -> Result<User<'_, Self>, Error> {
        authenticate(self, password, |password_ptr, temp_password_ptr| unsafe {
            nitrokey_sys::NK_user_authenticate(password_ptr, temp_password_ptr)
        })
    }

    fn authenticate_admin(&mut self, password: &str) -> Result<Admin<'_, Self>, Error> {
        authenticate(self, password, |password_ptr, temp_password_ptr| unsafe {
            nitrokey_sys::NK_first_authenticate(password_ptr, temp_password_ptr)
        })
    }
}
