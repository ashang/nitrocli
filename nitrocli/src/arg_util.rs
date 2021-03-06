// arg_util.rs

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

macro_rules! count {
  ($head:ident) => { 1 };
  ($head:ident, $($tail:ident),*) => {
    1 + count!($($tail),*)
  }
}

/// A macro for generating an enum with a set of simple (i.e., no
/// parameters) variants and their textual representations.
// TODO: Right now we hard code the derives we create. We may want to
//       make this set configurable.
macro_rules! Enum {
  ( $name:ident, [ $( $var:ident => ($str:expr, $exec:expr) ), *] ) => {
    Enum! {$name, [
      $( $var => $str ),*
    ]}

    #[allow(unused_qualifications)]
    impl $name {
      fn execute(
        self,
        ctx: &mut crate::args::ExecCtx<'_>,
        args: ::std::vec::Vec<::std::string::String>,
      ) -> crate::Result<()> {
        match self {
          $(
            $name::$var => $exec(ctx, args),
          )*
        }
      }
    }
  };
  ( $name:ident, [ $( $var:ident => $str:expr ), *] ) => {
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum $name {
      $(
        $var,
      )*
    }

    impl $name {
      #[allow(unused)]
      pub fn all(&self) -> [$name; count!($($var),*) ] {
        $name::all_variants()
      }

      pub fn all_variants() -> [$name; count!($($var),*) ] {
        [
          $(
            $name::$var,
          )*
        ]
      }
    }

    impl AsRef<str> for $name {
      fn as_ref(&self) -> &'static str {
        match *self {
          $(
            $name::$var => $str,
          )*
        }
      }
    }

    impl ::std::fmt::Display for $name {
      fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{}", self.as_ref())
      }
    }

    impl ::std::str::FromStr for $name {
      type Err = ();

      fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        match s {
          $(
            $str => Ok($name::$var),
          )*
          _ => Err(()),
        }
      }
    }
  };
}

/// A macro for formatting the variants of an enum (as created by the
/// Enum!{} macro) ready to be used in a help text. The supplied `fmt`
/// needs to contain the named parameter `{variants}`, which will be
/// replaced with a generated version of the enum's variants.
macro_rules! fmt_enum {
  ( $enm:ident ) => {{
    fmt_enum!($enm.all())
  }};
  ( $all:expr ) => {{
    $all
      .iter()
      .map(::std::convert::AsRef::as_ref)
      .collect::<::std::vec::Vec<_>>()
      .join("|")
  }};
}

/// A macro for generating the help text for a command/subcommand. The
/// argument is the variable representing the command (which in turn is
/// an enum).
/// Note that the name of this variable is embedded into the help text!
macro_rules! cmd_help {
  ( $cmd:ident ) => {
    format!(
      concat!("The ", stringify!($cmd), " to execute ({})"),
      fmt_enum!($cmd)
    )
  };
}

#[cfg(test)]
mod tests {
  Enum! {Command, [
    Var1 => "var1",
    Var2 => "2",
    Var3 => "crazy"
  ]}

  #[test]
  fn all_variants() {
    assert_eq!(
      Command::all_variants(),
      [Command::Var1, Command::Var2, Command::Var3]
    )
  }

  #[test]
  fn text_representations() {
    assert_eq!(Command::Var1.as_ref(), "var1");
    assert_eq!(Command::Var2.as_ref(), "2");
    assert_eq!(Command::Var3.as_ref(), "crazy");
  }
}
