// pws.rs

// *************************************************************************
// * Copyright (C) 2019 Daniel Mueller (deso@posteo.net)                   *
// *                                                                       *
// * This program is free software: you can redistribute it and/or modify  *
// * it under the terms of the GNU General Public License as published by  *
// * the Free Software Foundation, either version 3 of the License, or     *
// * (at your option) any later version.                                   *
// *                                                                       *
// * This program is distributed in the hope that it will be useful,       *
// * but WITHOUT ANY WARRANTY; without even the implied warranty of        *
// * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
// * GNU General Public License for more details.                          *
// *                                                                       *
// * You should have received a copy of the GNU General Public License     *
// * along with this program.  If not, see <http://www.gnu.org/licenses/>. *
// *************************************************************************

use super::*;

#[test_device]
fn set_invalid_slot(device: nitrokey::DeviceWrapper) {
  let res = Nitrocli::with_dev(device).handle(&["pws", "set", "100", "name", "login", "1234"]);

  assert_eq!(
    res.unwrap_cmd_err(),
    (
      Some("Could not write PWS slot"),
      nitrokey::CommandError::InvalidSlot
    )
  );
}

#[test_device]
fn status(device: nitrokey::DeviceWrapper) -> crate::Result<()> {
  let re = regex::Regex::new(
    r#"^slot\tname
(\d+\t.+\n)+$"#,
  )
  .unwrap();

  let mut ncli = Nitrocli::with_dev(device);
  // Make sure that we have at least something to display by ensuring
  // that there are there is one slot programmed.
  let _ = ncli.handle(&["pws", "set", "0", "the-name", "the-login", "123456"])?;

  let out = ncli.handle(&["pws", "status"])?;
  assert!(re.is_match(&out), out);
  Ok(())
}

#[test_device]
fn set_get(device: nitrokey::DeviceWrapper) -> crate::Result<()> {
  const NAME: &str = "dropbox";
  const LOGIN: &str = "d-e-s-o";
  const PASSWORD: &str = "my-secret-password";

  let mut ncli = Nitrocli::with_dev(device);
  let _ = ncli.handle(&["pws", "set", "1", &NAME, &LOGIN, &PASSWORD])?;

  let out = ncli.handle(&["pws", "get", "1", "--quiet", "--name"])?;
  assert_eq!(out, format!("{}\n", NAME));

  let out = ncli.handle(&["pws", "get", "1", "--quiet", "--login"])?;
  assert_eq!(out, format!("{}\n", LOGIN));

  let out = ncli.handle(&["pws", "get", "1", "--quiet", "--password"])?;
  assert_eq!(out, format!("{}\n", PASSWORD));

  let out = ncli.handle(&["pws", "get", "1", "--quiet"])?;
  assert_eq!(out, format!("{}\n{}\n{}\n", NAME, LOGIN, PASSWORD));

  let out = ncli.handle(&["pws", "get", "1"])?;
  assert_eq!(
    out,
    format!(
      "name:     {}\nlogin:    {}\npassword: {}\n",
      NAME, LOGIN, PASSWORD
    ),
  );
  Ok(())
}

#[test_device]
fn clear(device: nitrokey::DeviceWrapper) -> crate::Result<()> {
  let mut ncli = Nitrocli::with_dev(device);
  let _ = ncli.handle(&["pws", "set", "10", "clear-test", "some-login", "abcdef"])?;
  let _ = ncli.handle(&["pws", "clear", "10"])?;
  let res = ncli.handle(&["pws", "get", "10"]);

  assert_eq!(
    res.unwrap_cmd_err(),
    (
      Some("Could not access PWS slot"),
      nitrokey::CommandError::SlotNotProgrammed
    )
  );
  Ok(())
}
