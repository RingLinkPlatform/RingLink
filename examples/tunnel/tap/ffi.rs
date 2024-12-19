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

use libc::sockaddr;
use libc::{c_char, c_int, c_short, c_uchar, c_uint, c_ulong, c_ushort};

const IF_NAMESIZE: usize = 16;

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct ifmap {
    pub mem_start: c_ulong,
    pub mem_end: c_ulong,
    pub base_addr: c_ushort,
    pub irq: c_uchar,
    pub dma: c_uchar,
    pub port: c_uchar,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct ifreq {
    pub ifr_ifrn: ifreq_ifrn,
    pub ifr_ifru: ifreq_ifru,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub union ifreq_ifrn {
    pub ifrn_name: [c_char; IF_NAMESIZE],
    _bindgen_union_align: [u8; 16usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub union ifreq_ifru {
    pub ifru_addr: sockaddr,
    pub ifru_dstaddr: sockaddr,
    pub ifru_broadaddr: sockaddr,
    pub ifru_netmask: sockaddr,
    pub ifru_hwaddr: sockaddr,
    pub ifru_flags: c_short,
    pub ifru_ivalue: c_int,
    pub ifru_mtu: c_int,
    pub ifru_map: ifmap,
    pub ifru_slave: [c_char; 16usize],
    pub ifru_newname: [c_char; IF_NAMESIZE],
    pub ifru_data: *mut c_char,
    _bindgen_union_align: [u64; 3usize],
}

pub mod req {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::ops::{Deref, DerefMut};

    use libc::{c_char, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6, ARPHRD_ETHER};

    use super::ifreq;
    use super::IF_NAMESIZE;

    pub struct IfReq(ifreq);

    impl Deref for IfReq {
        type Target = ifreq;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl DerefMut for IfReq {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl IfReq {
        pub fn new(name: &str) -> Self {
            let mut req: ifreq = unsafe { std::mem::zeroed() };

            if !name.is_empty() {
                let mut if_name = [0u8; IF_NAMESIZE];
                let max_len = std::cmp::min(name.len(), IF_NAMESIZE);

                unsafe {
                    std::ptr::copy_nonoverlapping(name.as_ptr(), if_name.as_mut_ptr(), max_len);

                    req.ifr_ifrn.ifrn_name = std::mem::transmute(if_name);
                }
            }

            IfReq(req)
        }

        pub fn set_flags(&mut self, flags: i16) {
            self.0.ifr_ifru.ifru_flags = flags;
        }

        pub fn set_hwaddr(&mut self, mac: [u8; 6]) {
            unsafe {
                self.0.ifr_ifru.ifru_hwaddr.sa_family = ARPHRD_ETHER;
                self.0.ifr_ifru.ifru_hwaddr.sa_data[..6]
                    .copy_from_slice(&*(mac.as_ref() as *const [u8] as *const [c_char]));
            }
        }

        pub fn set_mtu(&mut self, mtu: u16) {
            self.0.ifr_ifru.ifru_mtu = mtu as i32;
        }

        pub fn set_ipv4(&mut self, addr: Ipv4Addr) {
            unsafe {
                let addr_u = &mut self.0.ifr_ifru.ifru_addr;
                let addr_in: &mut sockaddr_in = std::mem::transmute(addr_u);

                addr_in.sin_family = AF_INET as u16;
                addr_in.sin_addr.s_addr = u32::from_le_bytes(addr.octets());
            }
        }

        pub fn set_ipv4_mask(&mut self, prefix: u8) {
            let mask = u32::MAX.checked_shl((32 - prefix) as u32).unwrap_or(0);
            unsafe {
                let addr_u = &mut self.0.ifr_ifru.ifru_netmask;
                let addr_in: &mut sockaddr_in = std::mem::transmute(addr_u);

                addr_in.sin_family = AF_INET as u16;
                addr_in.sin_addr.s_addr = mask.to_be();
            }
        }

        pub fn set_ipv6(&mut self, addr: Ipv6Addr) {
            unsafe {
                let addr_u = &mut self.0.ifr_ifru.ifru_addr;
                let addr_in: &mut sockaddr_in6 = std::mem::transmute(addr_u);

                addr_in.sin6_family = AF_INET6 as u16;
                addr_in.sin6_addr.s6_addr.copy_from_slice(&addr.octets());
            }
        }
    }
}

const _IOC_NRBITS: u32 = 8;
const _IOC_TYPEBITS: u32 = 8;
const _IOC_SIZEBITS: u32 = 14;
const _IOC_DIRBITS: u32 = 2;

const _IOC_NRMASK: u32 = (1 << _IOC_NRBITS) - 1;
const _IOC_TYPEMASK: u32 = (1 << _IOC_TYPEBITS) - 1;
const _IOC_SIZEMASK: u32 = (1 << _IOC_SIZEBITS) - 1;
const _IOC_DIRMASK: u32 = (1 << _IOC_DIRBITS) - 1;

const _IOC_NRSHIFT: u32 = 0;
const _IOC_TYPESHIFT: u32 = _IOC_NRSHIFT + _IOC_NRBITS;
const _IOC_SIZESHIFT: u32 = _IOC_TYPESHIFT + _IOC_TYPEBITS;
const _IOC_DIRSHIFT: u32 = _IOC_SIZESHIFT + _IOC_SIZEBITS;

const _IOC_NONE: u32 = 0;
const _IOC_WRITE: u32 = 1;
const _IOC_READ: u32 = 2;

#[allow(non_snake_case)]
const fn _IOC(dir: u32, type_: u32, nr: u32, size: u32) -> u32 {
    ((dir) << _IOC_DIRSHIFT)
        | ((type_) << _IOC_TYPESHIFT)
        | ((nr) << _IOC_NRSHIFT)
        | ((size) << _IOC_SIZESHIFT)
}

#[allow(non_snake_case)]
const fn _IOW<T>(type_: u32, nr: u32) -> u32 {
    _IOC(_IOC_WRITE, type_, nr, std::mem::size_of::<T>() as u32)
}

pub const TUNSETIFF: u64 = _IOW::<c_int>('T' as u32, 202) as u64;
pub const TUNSETOFFLOAD: u64 = _IOW::<c_uint>('T' as u32, 208) as u64;
