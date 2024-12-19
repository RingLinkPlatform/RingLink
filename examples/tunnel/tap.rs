/*
 * Copyright 2024 RingNet
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::Result;
use libc::{c_short, IFF_MULTI_QUEUE, IFF_NO_PI, IFF_TAP, IFF_UP};

use ffi::req::IfReq;

mod bindings;
mod ffi;

const TUN_DEV_PATH: &'static str = "/dev/net/tun";

/// Control the TAP device
pub struct TapControl {
    ctl_socket: i32,
    name: String,
}

impl TapControl {
    pub fn new(name: &str) -> Result<TapControl> {
        let ctl_socket = bindings::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;

        Ok(TapControl {
            ctl_socket,
            name: name.to_string(),
        })
    }

    /// Set mtu of the TAP device.
    pub fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        let mut if_req = IfReq::new(&self.name);
        if_req.set_mtu(mtu);

        bindings::siocsifmtu(self.ctl_socket, if_req)?;

        Ok(())
    }

    /// Set ipv4 address of the TAP device.
    pub fn add_ipv4(&self, ip: Ipv4Addr, prefix: u8) -> Result<()> {
        let mut if_req = IfReq::new(&self.name);
        if_req.set_ipv4(ip);

        bindings::siocsifaddr(self.ctl_socket, if_req)?;

        let mut if_req = IfReq::new(&self.name);
        if_req.set_ipv4_mask(prefix);
        bindings::siocsifnetmask(self.ctl_socket, if_req)?;

        Ok(())
    }

    /// Set ipv6 address of the TAP device.
    pub fn add_ipv6(&self, ip: Ipv6Addr, _prefix: u8) -> Result<()> {
        let mut if_req = IfReq::new(&self.name);
        if_req.set_ipv6(ip);

        bindings::siocsifaddr(self.ctl_socket, if_req)?;

        Ok(())
    }

    /// Set mac address of the TAP device.
    pub fn set_mac(&mut self, mac: [u8; 6]) -> Result<()> {
        let mut if_req = IfReq::new(&self.name);
        if_req.set_hwaddr(mac);

        bindings::siocsifhwaddr(self.ctl_socket, if_req)?;

        Ok(())
    }

    pub fn up(&mut self) -> Result<()> {
        let mut if_req = IfReq::new(&self.name);
        if_req.set_flags((IFF_NO_PI | IFF_TAP | IFF_UP) as i16);

        bindings::siocsifflags(self.ctl_socket, if_req)?;

        Ok(())
    }

    /// open a new tap device use `IFF_MULTI_QUEUE`
    pub fn open(&self) -> Result<IO> {
        let mut if_req = IfReq::new(&self.name);
        if_req.ifr_ifru.ifru_flags = (IFF_NO_PI | IFF_TAP | IFF_MULTI_QUEUE) as c_short;

        let fd = bindings::open(TUN_DEV_PATH, libc::O_RDWR)?;

        bindings::tunsetiff(fd, if_req)?;

        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        Ok(IO::new(fd))
    }
}

/// An object providing IO operations to an TAP device opened by `TapControl`
///
/// IO can be shared between multiple threads using `Arc`
pub struct IO {
    fd: OwnedFd,
}

impl IO {
    pub(crate) fn new(fd: OwnedFd) -> Self {
        IO { fd }
    }

    /// Reads some bytes from the backend tap device.
    #[inline(always)]
    pub fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match bindings::read(self.fd.as_raw_fd(), buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    // wait read available
                    match self.wait_read() {
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            // timeout, return a WouldBlock to allow stop
                            return Err(e);
                        }
                        Err(e) => {
                            // other error
                            return Err(e);
                        }
                        _ => {
                            // read available, retry
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Writes some bytes to the backend tap device.
    pub fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        bindings::write(self.fd.as_raw_fd(), buf)
    }

    /// Wait for read
    ///
    /// Use [select] to wait fd
    ///
    /// # Returns
    /// Ok(_) if fd can read without block,
    /// Err(WouldBlock) to try again
    /// Err(e) if any error
    #[inline(always)]
    fn wait_read(&self) -> std::io::Result<()> {
        let mut fd_set = unsafe {
            let mut fd_set = MaybeUninit::zeroed().assume_init();
            libc::FD_ZERO(&mut fd_set);
            libc::FD_SET(self.fd.as_raw_fd(), &mut fd_set);
            fd_set
        };

        let r = bindings::select(self.fd.as_raw_fd() + 1, Some(&mut fd_set), None);
        if r < 0 {
            Err(std::io::Error::last_os_error())
        } else if r == 0 {
            // timeout
            return Err(std::io::Error::from(ErrorKind::WouldBlock));
        } else {
            Ok(())
        }
    }
}
