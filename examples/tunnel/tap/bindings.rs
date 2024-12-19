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

#![allow(dead_code)]

use std::ffi::CString;
use std::ptr::null_mut;
use cfg_if::cfg_if;
use libc::{c_int, fd_set};
use super::ffi::req::IfReq;
use super::ffi::{TUNSETIFF, TUNSETOFFLOAD};

pub fn tunsetiff(fd: i32, req: IfReq) -> std::io::Result<()> {
    cfg_if! {
        if #[cfg(target_env = "musl")] {
            let r = unsafe { libc::ioctl(fd, TUNSETIFF as i32, &*req) };
        } else {
            let r = unsafe { libc::ioctl(fd, TUNSETIFF, &*req) };
        }
    }

    if r == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn tunsetoffload(fd: i32, tun_tcp_offloads: u32) -> std::io::Result<()> {
    cfg_if! {
        if #[cfg(target_env = "musl")] {
            let r = unsafe {
                libc::ioctl(fd, TUNSETOFFLOAD as i32, tun_tcp_offloads)
            };
        } else {
            let r = unsafe {
                libc::ioctl(fd, TUNSETOFFLOAD, tun_tcp_offloads)
            };
        }
    }

    if r == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn siocsifhwaddr(fd: i32, req: IfReq) -> std::io::Result<()> {
    cfg_if! {
        if #[cfg(target_env = "musl")] {
            let r = unsafe { libc::ioctl(fd, libc::SIOCSIFHWADDR as i32, &*req) };
        } else {
            let r = unsafe { libc::ioctl(fd, libc::SIOCSIFHWADDR, &*req) };
        }
    }

    if r == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn siocsifmtu(fd: i32, req: IfReq) -> std::io::Result<()> {
    cfg_if! {
        if #[cfg(target_env = "musl")] {
            let r = unsafe { libc::ioctl(fd, libc::SIOCSIFMTU as i32, &*req) };
        } else {
            let r = unsafe { libc::ioctl(fd, libc::SIOCSIFMTU, &*req) };
        }
    }

    if r == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn siocsifaddr(fd: i32, req: IfReq) -> std::io::Result<()> {
    cfg_if! {
        if #[cfg(target_env = "musl")] {
            let r = unsafe { libc::ioctl(fd, libc::SIOCSIFADDR as i32, &*req) };
        } else {
            let r = unsafe { libc::ioctl(fd, libc::SIOCSIFADDR, &*req) };
        }
    }

    if r == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn siocsifnetmask(fd: i32, req: IfReq) -> std::io::Result<()> {
    cfg_if! {
        if #[cfg(target_env = "musl")] {
            let r = unsafe { libc::ioctl(fd, libc::SIOCSIFNETMASK as i32, &*req) };
        } else {
            let r = unsafe { libc::ioctl(fd, libc::SIOCSIFNETMASK, &*req) };
        }
    }

    if r == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn siocsifflags(fd: i32, req: IfReq) -> std::io::Result<()> {
    cfg_if! {
        if #[cfg(target_env = "musl")] {
            let r = unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS as i32, &*req) };
        } else {
            let r = unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS, &*req) };
        }
    }

    if r == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}


/// bindings to libc open
pub fn open(path: &str, flags: i32) -> std::io::Result<i32> {
    let path = CString::new(path)?;

    let fd = unsafe { libc::open(path.as_ptr(), flags) };

    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> std::io::Result<i32> {
    let fd = unsafe { libc::socket(domain, ty, protocol) };

    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

pub fn close(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}

pub fn select(nfds: c_int, rfds: Option<&mut fd_set>, wfds: Option<&mut fd_set>) -> c_int {
    let mut timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };

    unsafe {
        libc::select(
            nfds,
            rfds.map(|it| it as *mut _).unwrap_or(null_mut()),
            wfds.map(|it| it as *mut _).unwrap_or(null_mut()),
            null_mut(),
            &mut timeout,
        )
    }
}

#[inline(always)]
pub fn read(fd: i32, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };

    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[inline(always)]
pub fn write(fd: i32, buf: &[u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };

    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

pub fn fsync(fd: i32) -> std::io::Result<()> {
    let n = unsafe { libc::fsync(fd) };

    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
